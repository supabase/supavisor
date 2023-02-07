defmodule PgEdge.DbHandler do
  require Logger
  use GenServer
  alias PgEdge.Protocol.Server

  def start_link(config) do
    GenServer.start_link(__MODULE__, config)
  end

  @impl true
  @spec init(map()) :: {:ok, map()}
  def init(args) do
    # IP
    # {:ok, host} =
    #   Application.get_env(:pg_edge, :db_host)
    #   |> String.to_charlist()
    #   |> :inet.parse_address()

    state = %{
      check_ref: make_ref(),
      socket: nil,
      caller: nil,
      sent: false,
      auth: args.auth,
      tenant: args.tenant,
      buffer: "",
      db_state: nil,
      parameter_status: %{},
      state: nil,
      nonce: nil,
      server_proof: nil
    }

    send(self(), :connect)
    {:ok, state}
  end

  @impl true
  def handle_call(:change_owner, {pid, _}, state) do
    resp =
      case :gen_tcp.controlling_process(state.socket, pid) do
        :ok -> {:ok, state.socket}
        error -> error
      end

    {:reply, resp, state}
  end

  @impl true
  def handle_info(:connect, %{auth: auth, check_ref: ref} = state) do
    Logger.info("Try to connect to DB")
    Process.cancel_timer(ref)
    socket_opts = [:binary, {:packet, :raw}, {:active, true}]

    case :gen_tcp.connect(auth.host, auth.port, socket_opts) do
      {:ok, socket} ->
        Logger.debug("auth #{inspect(auth, pretty: true)}")

        # TODO: add password
        msg =
          :pgo_protocol.encode_startup_message([
            {"user", auth.user},
            {"database", auth.database},
            # {"password", auth.user},
            {"application_name", auth.application_name}
          ])

        :ok = :gen_tcp.send(socket, msg)
        {:noreply, %{state | state: :authentication, socket: socket}}

      other ->
        Logger.error("Connection faild #{inspect(other)}")
        {:noreply, %{state | check_ref: reconnect()}}
    end
  end

  def handle_info({:tcp, _port, bin}, %{state: :authentication} = state) do
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
                  state.auth.user
                  |> :pgo_scram.get_client_first(nonce)

                client_first_size = IO.iodata_length(client_first)

                sasl_initial_response = [
                  <<"SCRAM-SHA-256">>,
                  0,
                  <<client_first_size::32-integer>>,
                  client_first
                ]

                bin = :pgo_protocol.encode_scram_response_message(sasl_initial_response)
                :gen_tcp.send(state.socket, bin)
                nonce

              other ->
                Logger.error("Undefined sasl method #{other}")
                nil
            end

          {ps, :authentication_sasl, nonce}

        %{payload: {:authentication_server_first_message, server_first}}, {ps, _} ->
          nonce = state.nonce
          server_first_parts = :pgo_scram.parse_server_first(server_first, nonce)

          {client_final_message, server_proof} =
            :pgo_scram.get_client_final(
              server_first_parts,
              nonce,
              state.auth.user,
              state.auth.password.()
            )

          bin = :pgo_protocol.encode_scram_response_message(client_final_message)
          :gen_tcp.send(state.socket, bin)

          {ps, :authentication_server_first_message, server_proof}

        %{payload: {:authentication_server_final_message, _server_final}}, acc ->
          acc

        _e, acc ->
          acc
      end)

    case resp do
      {_, :authentication_sasl, nonce} ->
        {:noreply, %{state | nonce: nonce}}

      {_, :authentication_server_first_message, server_proof} ->
        {:noreply, %{state | server_proof: server_proof}}

      {ps, db_state} ->
        Logger.debug("parameter_status: #{inspect(ps, pretty: true)}")
        Logger.debug("DB ready_for_query: #{inspect(db_state)}")
        {:noreply, %{state | parameter_status: ps, state: :idle}}
    end
  end

  def handle_info({:tcp_closed, _port}, state) do
    Logger.error("DB closed connection #{inspect(self())}")
    {:noreply, %{state | check_ref: reconnect(), socket: nil}}
  end

  def handle_info(msg, state) do
    msg = [
      {"msg", msg},
      {"state", state}
    ]

    Logger.error("Undefined msg: #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  def terminate(_reason, _state, _data) do
    Logger.debug("DB terminated")
    :ok
  end

  def handle_packets(<<char::integer-8, pkt_len::integer-32, rest::binary>> = bin) do
    payload_len = pkt_len - 4
    tag = Server.tag(char)

    case rest do
      <<payload::binary-size(payload_len)>> ->
        pkt = Server.packet(tag, pkt_len, payload)
        Logger.debug(inspect(pkt, pretty: true))

        {:ok, tag, "", pkt.payload}

      <<payload::binary-size(payload_len), rest1::binary>> ->
        pkt = Server.packet(tag, pkt_len, payload)
        Logger.debug(inspect(pkt, pretty: true))

        handle_packets(rest1)

      _ ->
        {:ok, tag, bin, ""}
    end
  end

  def handle_packets(bin) do
    {:ok, :small_chunk, bin, ""}
  end

  def reconnect() do
    Process.send_after(self(), :connect, 5_000)
  end

  def send_active_once(socket, msg) do
    :gen_tcp.send(socket, msg)
    :inet.setopts(socket, [{:active, :once}])
  end

  def active_once(socket) do
    :inet.setopts(socket, [{:active, :once}])
  end
end
