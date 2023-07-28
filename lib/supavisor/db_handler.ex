defmodule Supavisor.DbHandler do
  @moduledoc """
  This module contains functions to start a link with the database, send requests to the database, and handle incoming messages from clients.
  It uses the Supavisor.Protocol.Server module to decode messages from the database and sends messages to clients Supavisor.ClientHandler.
  """

  @type tcp_sock :: {:gen_tcp, :gen_tcp.socket()}
  @type ssl_sock :: {:ssl, :ssl.sslsocket()}
  @type sock :: tcp_sock() | ssl_sock()

  require Logger

  @behaviour :gen_statem

  alias Supavisor.ClientHandler, as: Client
  alias Supavisor.Helpers, as: H
  alias Supavisor.{Protocol.Server, Monitoring.Telem}

  @reconnect_timeout 2_500

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
      id: args.id,
      sock: nil,
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

    sock_opts = [
      :binary,
      {:packet, :raw},
      {:active, false},
      auth.ip_version
    ]

    reconnect_callback = {:keep_state_and_data, {:state_timeout, @reconnect_timeout, :connect}}

    case :gen_tcp.connect(auth.host, auth.port, sock_opts) do
      {:ok, sock} ->
        Logger.debug("auth #{inspect(auth, pretty: true)}")

        case try_ssl_handshake({:gen_tcp, sock}, auth) do
          {:ok, sock} ->
            # TODO: fix user name
            case send_startup(sock, auth) do
              :ok ->
                :ok = activate(sock)
                {:next_state, :authentication, %{data | sock: sock}}

              {:error, reason} ->
                Logger.error("Send startup error #{inspect(reason)}")
                reconnect_callback
            end

          {:error, error} ->
            Logger.error("Handshake error #{inspect(error)}")
            reconnect_callback
        end

      other ->
        Logger.error("Connection failed #{inspect(other)}")
        reconnect_callback
    end
  end

  def handle_event(:state_timeout, :connect, _state, _) do
    Logger.warning("Reconnect")
    {:keep_state_and_data, {:next_event, :internal, :connect}}
  end

  def handle_event(:info, {_proto, _, bin}, :authentication, data) do
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
              {:ok, req_method, _} ->
                Logger.debug("SASL method #{inspect(req_method)}")
                nonce = :pgo_scram.get_nonce(16)
                user = get_user(data.auth)
                client_first = :pgo_scram.get_client_first(user, nonce)
                client_first_size = IO.iodata_length(client_first)

                sasl_initial_response = [
                  <<"SCRAM-SHA-256">>,
                  0,
                  <<client_first_size::32-integer>>,
                  client_first
                ]

                bin = :pgo_protocol.encode_scram_response_message(sasl_initial_response)
                :ok = sock_send(data.sock, bin)
                nonce

              other ->
                Logger.error("Undefined sasl method #{inspect(other)}")
                nil
            end

          {ps, :authentication_sasl, nonce}

        %{payload: {:authentication_server_first_message, server_first}}, {ps, _}
        when data.auth.require_user == false ->
          nonce = data.nonce
          server_first_parts = H.parse_server_first(server_first, nonce)

          {client_final_message, server_proof} =
            H.get_client_final(
              :auth_query,
              data.auth.secrets.(),
              server_first_parts,
              nonce,
              data.auth.secrets.().user,
              "biws"
            )

          bin = :pgo_protocol.encode_scram_response_message(client_final_message)
          :ok = sock_send(data.sock, bin)

          {ps, :authentication_server_first_message, server_proof}

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
          :ok = sock_send(data.sock, bin)

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

          :ok = sock_send(data.sock, bin)

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
        Supavisor.set_parameter_status(data.id, ps)

        {:next_state, :idle, %{data | parameter_status: ps},
         {:next_event, :internal, :check_buffer}}
    end
  end

  def handle_event(:internal, :check_buffer, :idle, %{buffer: buff} = data) do
    if buff != [] do
      Logger.warning("Buffer is not empty, try to send #{IO.iodata_length(buff)} bytes")
      buff = Enum.reverse(buff)
      :ok = sock_send(data.sock, buff)
    end

    {:keep_state, %{data | buffer: []}}
  end

  def handle_event(:info, {_proto, _, bin}, _, data) do
    # check if the response ends with "ready for query"
    ready = String.ends_with?(bin, <<?Z, 5::32, ?I>>)
    :ok = Client.client_call(data.caller, bin, ready)

    if ready do
      Telem.network_usage(:db, data.sock, data.tenant, data.user_alias)
    end

    :keep_state_and_data
  end

  def handle_event({:call, {pid, _} = from}, {:db_call, bin}, :idle, %{sock: sock} = data) do
    reply = {:reply, from, sock_send(sock, bin)}
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

  def handle_event(:info, {:tcp_closed, sock}, state, %{sock: sock} = data) do
    Logger.error("Connection closed when state was #{state}")
    {:next_state, :connect, data, {:state_timeout, 2_500, :connect}}
  end

  def handle_event(:info, {:ssl_closed, sock}, state, %{sock: sock} = data) do
    Logger.error("Connection closed when state was #{state}")
    {:next_state, :connect, data, {:state_timeout, 2_500, :connect}}
  end

  # linked client_handler went down
  def handle_event(_, {:EXIT, pid, reason}, state, data) do
    Logger.error("Client handler #{inspect(pid)} went down with reason #{inspect(reason)}")

    if state == :idle do
      :ok = sock_send(data.sock, <<?X, 4::32>>)
      :ok = :gen_tcp.close(elem(data.sock, 1))
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

  @spec try_ssl_handshake(tcp_sock, map) :: {:ok, sock} | {:error, term()}
  defp try_ssl_handshake(sock, %{upstream_ssl: true} = auth) do
    case sock_send(sock, Server.ssl_request()) do
      :ok -> ssl_recv(sock, auth)
      error -> error
    end
  end

  defp try_ssl_handshake(sock, _), do: {:ok, sock}

  @spec ssl_recv(tcp_sock, map) :: {:ok, ssl_sock} | {:error, term}
  defp ssl_recv({:gen_tcp, sock} = s, auth) do
    case :gen_tcp.recv(sock, 1, 15_000) do
      {:ok, <<?S>>} ->
        ssl_connect(s, auth)

      {:ok, <<?N>>} ->
        {:error, :ssl_not_available}

      {:error, _} = error ->
        error
    end
  end

  @spec ssl_connect(tcp_sock, map, pos_integer) :: {:ok, ssl_sock} | {:error, term}
  defp ssl_connect({:gen_tcp, sock}, auth, timeout \\ 5000) do
    opts =
      case auth.upstream_verify do
        :peer ->
          [
            verify: :verify_peer,
            cacerts: [auth.upstream_tls_ca],
            customize_hostname_check: [{:match_fun, fn _, _ -> true end}]
          ]

        :none ->
          [verify: :verify_none]
      end

    case :ssl.connect(sock, opts, timeout) do
      {:ok, ssl_sock} ->
        {:ok, {:ssl, ssl_sock}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec send_startup(sock(), map()) :: :ok | {:error, term}
  defp send_startup(sock, auth) do
    user = get_user(auth)

    msg =
      :pgo_protocol.encode_startup_message([
        {"user", user},
        {"database", auth.database},
        {"application_name", auth.application_name}
      ])

    sock_send(sock, msg)
  end

  @spec sock_send(tcp_sock | ssl_sock, iodata) :: :ok | {:error, term}
  defp sock_send({mod, sock}, data) do
    mod.send(sock, data)
  end

  @spec activate(tcp_sock | ssl_sock) :: :ok | {:error, term}
  defp activate({:gen_tcp, sock}) do
    :inet.setopts(sock, active: true)
  end

  defp activate({:ssl, sock}) do
    :ssl.setopts(sock, active: true)
  end

  defp get_user(auth) do
    if auth.require_user do
      auth.user
    else
      auth.secrets.().user
    end
  end
end
