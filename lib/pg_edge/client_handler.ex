defmodule PgEdge.ClientHandler do
  require Logger
  use GenServer
  @behaviour :ranch_protocol

  alias PgEdge.Protocol.Client
  alias PgEdge.Protocol.Server
  alias PgEdge.DbHandler, as: Db

  @impl true
  def start_link(ref, _socket, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  def client_call(pid, bin, ready?) do
    GenServer.call(pid, {:client_call, bin, ready?})
  end

  @impl true
  def init(_opts) do
    {:ok, %{}}
  end

  def init(ref, trans, _opts) do
    {:ok, socket} = :ranch.handshake(ref)
    :ok = trans.setopts(socket, [{:active, true}])
    Logger.info("ClientHandler is: #{inspect(self())}")

    :gen_server.enter_loop(
      __MODULE__,
      [],
      %{
        socket: socket,
        trans: trans,
        connected: false,
        buffer: "",
        db_pid: nil,
        tenant: nil,
        pool: nil,
        manager: nil,
        subscribe_ref: make_ref(),
        state: :wait_startup_packet
      }
    )
  end

  @impl true
  def handle_info(
        {:tcp, sock, bin},
        %{socket: socket, state: :wait_startup_packet} = state
      )
      when sock == socket do
    Logger.debug("Startup <-- bin #{inspect(byte_size(bin))}")

    # TODO: implement SSL negotiation
    # SSL negotiation, S/N/Error
    if byte_size(bin) == 8 do
      :gen_tcp.send(socket, "N")
      {:noreply, state}
    else
      hello = Client.decode_startup_packet(bin)
      Logger.warning("Client startup message: #{inspect(hello)}")

      external_id =
        hello.payload["user"]
        |> get_external_id()

      # TODO: check if tenant exists
      :gen_tcp.send(socket, authentication_ok())
      send(self(), :subscribe)
      {:noreply, %{state | state: :subscribing, tenant: external_id}}
    end
  end

  def handle_info(:subscribe, %{tenant: tenant} = state) do
    Process.cancel_timer(state.subscribe_ref)

    with {:ok, tenant_sup} <- PgEdge.start(tenant),
         {:ok,
          %{
            manager: manager,
            pool: pool
          }} <- PgEdge.subscribe_dist(node(tenant_sup), self(), tenant) do
      Process.monitor(manager)
      {:noreply, %{state | state: :idle, pool: pool, manager: manager}}
    else
      error ->
        Logger.error("Subscribe error: #{inspect(error)}")
        {:noreply, %{state | subscribe_ref: check_subscribe()}}
    end
  end

  def handle_info({:tcp, _, <<?X, 4::32>>}, state) do
    Logger.warn("Receive termination")
    {:noreply, state}
  end

  # select 1 stub
  def handle_info({:tcp, _, <<?Q, 14::32, "SELECT 1;", 0>>}, state) do
    Logger.info("Receive select 1")
    state.trans.send(state.socket, Server.select_1_response())
    {:noreply, state}
  end

  def handle_info({:tcp, _, bin}, %{buffer: buf, db_pid: db_pid, tenant: tenant} = state) do
    db_pid =
      if db_pid do
        db_pid
      else
        state.pool
        |> :poolboy.checkout(true, 60000)
      end

    data = buf <> bin

    buf =
      case Client.decode(data) do
        {:ok, packets, rest} ->
          Enum.each(packets, fn pkt ->
            Logger.info("Packet: #{inspect(pkt)}")
            Db.call(db_pid, pkt.bin)
          end)

          rest

        {:error, reason} ->
          Logger.error("Error: #{inspect(reason)}")
          data
      end

    {:noreply, %{state | buffer: buf, db_pid: db_pid}}
  end

  def handle_info({:tcp_closed, _}, state) do
    Logger.info("Client closed connection")
    {:stop, :normal, state}
  end

  def handle_info({:DOWN, _, _, _, _}, state) do
    Logger.error("Manager down tenant: #{state.tenant}")
    send(self(), :subscribe)
    {:noreply, %{state | state: :subscribing, pool: nil, manager: nil}}
  end

  def handle_info(msg, state) do
    msg = [
      {"msg", msg},
      {"state", state}
    ]

    Logger.error("Undefined msg: #{inspect(msg, pretty: true)}")

    {:noreply, state}
  end

  @impl true
  def handle_call(
        {:client_call, bin, ready?},
        _,
        %{socket: socket, trans: trans, db_pid: db_pid, tenant: tenant} = state
      ) do
    db_pid1 =
      if ready? do
        state.pool
        |> :poolboy.checkin(db_pid)

        nil
      else
        db_pid
      end

    Logger.debug("--> --> bin #{inspect(byte_size(bin))} bytes")
    trans.send(socket, bin)
    {:reply, :ok, %{state | db_pid: db_pid1}}
  end

  # TODO: implement authentication response
  def authentication_ok() do
    [
      # authentication_ok
      <<"R", 0, 0, 0, 8>>,
      <<0, 0, 0, 0>>,
      # parameter_status,<<"application_name">>,<<"nonode@nohost">>
      <<83, 0, 0, 0, 35>>,
      <<"application_name", 0, "nonode@nohost", 0>>,
      # parameter_status,<<"client_encoding">>,<<"UTF8">>
      <<83, 0, 0, 0, 25>>,
      <<99, 108, 105, 101, 110, 116, 95, 101, 110, 99, 111, 100, 105, 110, 103, 0, 85, 84, 70, 56,
        0>>,
      # parameter_status,<<"server_version">>,<<"14.1">>
      <<83, 0, 0, 0, 24>>,
      <<115, 101, 114, 118, 101, 114, 95, 118, 101, 114, 115, 105, 111, 110, 0, "14.1", 0>>,
      # parameter_status,<<"session_authorization">>,<<"postgres">>
      <<83, 0, 0, 0, 35>>,
      <<115, 101, 115, 115, 105, 111, 110, 95, 97, 117, 116, 104, 111, 114, 105, 122, 97, 116,
        105, 111, 110, 0, 112, 111, 115, 116, 103, 114, 101, 115, 0>>,
      # parameter_status,<<"standard_conforming_strings">>,<<"on">>
      <<83, 0, 0, 0, 35>>,
      <<115, 116, 97, 110, 100, 97, 114, 100, 95, 99, 111, 110, 102, 111, 114, 109, 105, 110, 103,
        95, 115, 116, 114, 105, 110, 103, 115, 0, 111, 110, 0>>,
      # parameter_status,<<"TimeZone">>,<<"Europe/Kiev">>
      <<83, 0, 0, 0, 25>>,
      <<84, 105, 109, 101, 90, 111, 110, 101, 0, 69, 117, 114, 111, 112, 101, 47, 75, 105, 101,
        118, 0>>,
      # backend_key_data,59194,2347138713
      <<75, 0, 0, 0, 12>>,
      <<0, 0, 231, 58, 139, 230, 126, 153>>,
      # ready_for_query,idle
      <<90, 0, 0, 0, 5>>,
      <<"I">>
    ]
  end

  ## Internal functions

  @spec get_external_id(String.t()) :: String.t()
  def get_external_id(username) do
    username
    |> String.split(".")
    |> List.last()
  end

  defp check_subscribe() do
    Process.send_after(self(), :subscribe, 1000)
  end
end
