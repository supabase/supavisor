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
    Logger.metadata(project: args.tenant)

    data = %{
      socket: nil,
      caller: nil,
      sent: false,
      auth: args.auth,
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
    socket_opts = [:binary, {:packet, :raw}, {:active, true}]

    case :gen_tcp.connect(auth.host, auth.port, socket_opts) do
      {:ok, socket} ->
        Logger.debug("auth #{inspect(auth, pretty: true)}")

        # TODO: add password
        msg =
          :pgo_protocol.encode_startup_message([
            {"user", auth.user},
            {"database", auth.database},
            {"application_name", auth.application_name}
          ])

        :ok = :gen_tcp.send(socket, msg)
        {:next_state, :authentication, %{data | socket: socket}}

      other ->
        Logger.error("Connection failed #{inspect(other)}")
        {:keep_state_and_data, {:state_timeout, 2_500, :connect}}
    end
  end

  def handle_event(:state_timeout, :connect, _state, _) do
    Logger.warning("Reconnect")
    {:keep_state_and_data, {:next_event, :internal, :connect}}
  end

  def handle_event(:info, {:tcp, _, bin}, :authentication, data) do
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
                :gen_tcp.send(data.socket, bin)
                nonce

              other ->
                Logger.error("Undefined sasl method #{other}")
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
          :gen_tcp.send(data.socket, bin)

          {ps, :authentication_server_first_message, server_proof}

        %{payload: {:authentication_server_final_message, _server_final}}, acc ->
          acc

        _e, acc ->
          acc
      end)

    case resp do
      {_, :authentication_sasl, nonce} ->
        {:keep_state, %{data | nonce: nonce}}

      {_, :authentication_server_first_message, server_proof} ->
        {:keep_state, %{data | server_proof: server_proof}}

      {ps, db_state} ->
        Logger.debug("DB ready_for_query: #{inspect(db_state)}")

        {:next_state, :idle, %{data | parameter_status: ps},
         {:next_event, :internal, :check_buffer}}
    end
  end

  def handle_event(:internal, :check_buffer, :idle, %{buffer: buff} = data) do
    if buff != [] do
      Logger.warning("Buffer is not empty, try to send #{IO.iodata_length(buff)} bytes")
      buff = Enum.reverse(buff)
      :ok = :gen_tcp.send(data.socket, buff)
    end

    {:keep_state, %{data | buffer: []}}
  end

  def handle_event(:info, {:tcp, _, bin}, _, data) do
    # check if the response ends with "ready for query"
    ready = String.ends_with?(bin, <<?Z, 5::32, ?I>>)
    :ok = Client.client_call(data.caller, bin, ready)

    if ready do
      Telem.network_usage(:db, data.socket, data.tenant)
    end

    :keep_state_and_data
  end

  def handle_event({:call, {pid, _} = from}, {:db_call, bin}, :idle, %{socket: socket} = data) do
    reply = {:reply, from, :gen_tcp.send(socket, bin)}
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

  # linked client_handler went down
  def handle_event(_, {:EXIT, pid, reason}, state, data) do
    Logger.error("Client handler #{inspect(pid)} went down with reason #{inspect(reason)}")

    if state == :idle do
      :ok = :gen_tcp.send(data.socket, <<?X, 4::32>>)
      :ok = :gen_tcp.close(data.socket)
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
end
