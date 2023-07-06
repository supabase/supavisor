defmodule Supavisor.DbHandler do
  @moduledoc """
  This module contains functions to start a link with the database, send requests to the database, and handle incoming messages from clients.
  It uses the Supavisor.Protocol.Server module to decode messages from the database and sends messages to clients Supavisor.ClientHandler.
  """

  require Logger

  @behaviour :gen_statem

  alias Supavisor.ClientHandler, as: Client
  alias Supavisor.{Protocol.Server, Monitoring.Telem}

  def start_link(config) do
    :gen_statem.start_link(__MODULE__, config, hibernate_after: 5_000)
  end

  @spec call(pid(), binary()) :: :ok | {:error, any()} | {:buffering, non_neg_integer()}
  def call(pid, msg) do
    :gen_statem.call(pid, {:db_call, msg})
  end

  @impl true
  def init(args) do
    Process.flag(:trap_exit, true)
    Logger.metadata(project: args.tenant, user: args.user_alias)

    data = %{
      socket: nil,
      caller: nil,
      sent: false,
      auth: args.auth,
      user_alias: args.user_alias,
      tenant: args.tenant,
      buffer: [],
      db_state: nil,
      parameter_status: %{},
      nonce: nil,
      messages: "",
      server_proof: nil
    }

    {:ok, :connect, data, {:next_event, :internal, :connect}}
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  @impl true
  def handle_event(:internal, _, :connect, %{auth: auth} = data) do
    Logger.info("Try to connect to DB")

    socket_opts = [
      :binary,
      {:packet, :raw},
      {:active, false},
      auth.ip_version
    ]

    case :gen_tcp.connect(auth.host, auth.port, socket_opts) do
      {:ok, socket} ->
        sock = {:gen_tcp, socket}

        case handshake(sock, auth) do
          {:ok, sock} ->
            # Back to active from here
            set_socket_opts(sock, [{:active, true}])
            {:next_state, :authentication, %{data | socket: sock}}

          {:error, error} ->
            Logger.error("Handshake error #{inspect(error)}")
            :gen_tcp.close(socket)
            {:keep_state_and_data, {:state_timeout, 2_500, :connect}}
        end

      other ->
        Logger.error("Connection failed #{inspect(other)}")
        {:keep_state_and_data, {:state_timeout, 2_500, :connect}}
    end
  end

  def handle_event(:state_timeout, :connect, _state, _) do
    Logger.warning("Reconnect")
    {:keep_state_and_data, {:next_event, :internal, :connect}}
  end

  def handle_event(:info, {tcp_or_ssl, _, bin}, :authentication, data)
      when tcp_or_ssl in [:tcp, :ssl] do
    dec_pkt = Server.decode(bin)
    Logger.debug("dec_pkt, #{inspect(dec_pkt, pretty: true)}")

    resp =
      Enum.reduce(dec_pkt, {%{}, nil}, fn
        %{tag: :parameter_status, payload: {k, v}}, {ps, db_state} ->
          {Map.put(ps, k, v), db_state}

        %{tag: :ready_for_query, payload: db_state}, {ps, _} ->
          {ps, db_state}

        %{payload: {:authentication_sasl_password, methods_b}}, {ps, _} ->
          nonce =
            case Server.decode_string(methods_b) do
              {:ok, "SCRAM-SHA-256", _} ->
                nonce = :pgo_scram.get_nonce(16)

                client_first =
                  data.auth.user
                  |> :pgo_scram.get_client_first(nonce)

                client_first_size = IO.iodata_length(client_first)

                sasl_initial_response = [
                  <<"SCRAM-SHA-256">>,
                  0,
                  <<client_first_size::32-integer>>,
                  client_first
                ]

                bin = :pgo_protocol.encode_scram_response_message(sasl_initial_response)
                sock_send(data.socket, bin)
                nonce

              other ->
                Logger.error("Undefined sasl method #{inspect(other)}")
                nil
            end

          {ps, :authentication_sasl, nonce}

        %{payload: {:authentication_server_first_message, server_first}}, {ps, _} ->
          nonce = data.nonce
          server_first_parts = :pgo_scram.parse_server_first(server_first, nonce)

          {client_final_message, server_proof} =
            :pgo_scram.get_client_final(
              server_first_parts,
              nonce,
              data.auth.user,
              data.auth.password.()
            )

          bin = :pgo_protocol.encode_scram_response_message(client_final_message)
          sock_send(data.socket, bin)

          {ps, :authentication_server_first_message, server_proof}

        %{payload: {:authentication_server_final_message, _server_final}}, acc ->
          acc

        %{payload: {:authentication_md5_password, salt}}, {ps, _} ->
          password = data.auth.password
          user = data.auth.user

          digest = [password.(), user] |> :erlang.md5() |> Base.encode16(case: :lower)
          digest = [digest, salt] |> :erlang.md5() |> Base.encode16(case: :lower)
          payload = ["md5", digest, 0]

          bin = [?p, <<IO.iodata_length(payload) + 4::signed-32>>, payload]

          sock_send(data.socket, bin)

          {ps, :authentication_md5}

        %{tag: :error_response, payload: error}, _ ->
          {:error_response, error}

        _e, acc ->
          acc
      end)

    case resp do
      {_, :authentication_sasl, nonce} ->
        {:keep_state, %{data | nonce: nonce}}

      {_, :authentication_server_first_message, server_proof} ->
        {:keep_state, %{data | server_proof: server_proof}}

      {_, :authentication_md5} ->
        {:keep_state, data}

      {:error_response, error} ->
        Logger.error("Error auth response #{inspect(error)}")
        {:keep_state, data}

      {ps, db_state} ->
        Logger.debug("DB ready_for_query: #{inspect(db_state)} #{inspect(ps, pretty: true)}")
        Supavisor.set_parameter_status(data.tenant, data.user_alias, ps)

        {:next_state, :idle, %{data | parameter_status: ps},
         {:next_event, :internal, :check_buffer}}
    end
  end

  def handle_event(:internal, :check_buffer, :idle, %{buffer: buff} = data) do
    if buff != [] do
      Logger.warning("Buffer is not empty, try to send #{IO.iodata_length(buff)} bytes")
      buff = Enum.reverse(buff)
      :ok = sock_send(data.socket, buff)
    end

    {:keep_state, %{data | buffer: []}}
  end

  def handle_event(:info, {tcp_or_ssl, _, bin}, _, data) when tcp_or_ssl in [:tcp, :ssl] do
    # check if the response ends with "ready for query"
    ready = String.ends_with?(bin, <<?Z, 5::32, ?I>>)
    :ok = Client.client_call(data.caller, bin, ready)

    # Does not appear to be matching func for SSL
    if ready && tcp_or_ssl == :tcp do
      Telem.network_usage(:db, elem(data.socket, 1), data.tenant, data.user_alias)
    end

    :keep_state_and_data
  end

  def handle_event({:call, {pid, _} = from}, {:db_call, bin}, :idle, %{socket: socket} = data) do
    reply = {:reply, from, sock_send(socket, bin)}
    {:keep_state, %{data | caller: pid}, reply}
  end

  def handle_event({:call, {pid, _} = from}, {:db_call, bin}, state, %{buffer: buff} = data) do
    Logger.warning(
      "state #{state} <-- <-- bin #{inspect(byte_size(bin))} bytes, caller: #{inspect(pid)}"
    )

    new_buff = [bin | buff]
    reply = {:reply, from, {:buffering, IO.iodata_length(new_buff)}}
    {:keep_state, %{data | caller: pid, buffer: new_buff}, reply}
  end

  def handle_event(:info, {:tcp_closed, socket}, state, %{socket: socket} = data) do
    Logger.error("Connection closed when state was #{state}")
    {:next_state, :connect, data, {:state_timeout, 2_500, :connect}}
  end

  def handle_event(:info, {:ssl_closed, socket}, state, %{socket: socket} = data) do
    Logger.error("Connection closed when state was #{state}")
    {:next_state, :connect, data, {:state_timeout, 2_500, :connect}}
  end

  # linked client_handler went down
  def handle_event(_, {:EXIT, pid, reason}, state, data) do
    Logger.error("Client handler #{inspect(pid)} went down with reason #{inspect(reason)}")

    if state == :idle do
      :ok = sock_send(data.socket, <<?X, 4::32>>)
      :ok = :gen_tcp.close(elem(data.socket, 1))
      {:stop, :normal, data}
    else
      {:keep_state, %{data | caller: nil, buffer: []}}
    end
  end

  def handle_event(type, content, state, data) do
    msg = [
      {"type", type},
      {"content", content},
      {"state", state},
      {"data", data}
    ]

    Logger.debug("Undefined msg: #{inspect(msg, pretty: true)}")

    :keep_state_and_data
  end

  # Adapted from Postgrex.Protocol
  # TODO: Pull over handshake timeout from Postgrex.Protocol?
  defp handshake(sock, %{ssl: true} = auth), do: ssl(sock, auth)
  defp handshake(sock, %{ssl: false} = auth), do: send_startup(sock, auth)

  defp ssl(sock, auth) do
    case sock_send(sock, ssl_request_bin()) do
      :ok -> ssl_recv(sock, auth)
      {:disconnect, _, _} = dis -> dis
    end
  end

  defp ssl_recv({:gen_tcp, sock} = s, auth) do
    case :gen_tcp.recv(sock, 1, :infinity) do
      {:ok, <<?S>>} ->
        ssl_connect(s, auth)

      {:ok, <<?N>>} ->
        Logger.error("SSL requested but server says it's not available")
        {:error, :ssl_not_available}

      {:error, reason} ->
        Logger.error("Error when receiving SSL response: #{inspect(reason)}", reason: reason)

        {:error, :ssl_connect_error}
    end
  end

  defp ssl_connect({:gen_tcp, sock}, auth) do
    case :ssl.connect(sock, [], :timer.seconds(30)) do
      {:ok, ssl_sock} ->
        send_startup({:ssl, ssl_sock}, auth)

      {:error, reason} ->
        Logger.error("Error when connecting with SSL: #{inspect(reason)}", reason: reason)

        {:error, :ssl_connect_error}
    end
  end

  defp send_startup(sock, auth) do
    msg =
      :pgo_protocol.encode_startup_message([
        {"user", auth.user},
        {"database", auth.database},
        {"application_name", auth.application_name}
      ])

    :ok = sock_send(sock, msg)
    {:ok, sock}
  end

  defp sock_send({mod, sock}, data) do
    mod.send(sock, data)
  end

  defp set_socket_opts({:gen_tcp, socket}, opts) do
    :inet.setopts(socket, opts)
  end

  defp set_socket_opts({:ssl, socket}, opts) do
    :ssl.setopts(socket, opts)
  end

  defp ssl_request_bin() do
    <<0, 0, 0, 8, 4, 210, 22, 47>>
  end
end
