defmodule PgEdge.ClientHandler do
  require Logger

  @behaviour :ranch_protocol
  @behaviour :gen_statem

  alias PgEdge.Protocol.Client
  alias PgEdge.DbHandler, as: Db

  @impl true
  def start_link(ref, _socket, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  def init(_opts), do: {:ok, %{}}

  @impl true
  def callback_mode,
    do: [
      :handle_event_function
      # :state_enter
    ]

  def client_call(pid, bin, ready?) do
    :gen_statem.call(pid, {:client_call, bin, ready?}, 5000)
  end

  def init(ref, trans, _opts) do
    Process.flag(:trap_exit, true)

    {:ok, socket} = :ranch.handshake(ref)
    :ok = trans.setopts(socket, [{:active, true}])
    Logger.info("ClientHandler is: #{inspect(self())}")

    data = %{
      socket: socket,
      trans: trans,
      db_pid: nil,
      tenant: nil,
      pool: nil,
      manager: nil
    }

    :gen_statem.enter_loop(__MODULE__, [], :negotiation, data)
  end

  def handle_event(:info, {:tcp, _, bin}, :negotiation, data) do
    # TODO: implement SSL negotiation
    # SSL negotiation, S/N/Error
    :gen_tcp.send(data.socket, "N")

    {:next_state, :auth, data}
  end

  def handle_event(:info, {:tcp, _, bin}, :auth, data) do
    hello = Client.decode_startup_packet(bin)
    Logger.warning("Client startup message: #{inspect(hello)}")

    external_id =
      hello.payload["user"]
      |> get_external_id()

    Logger.metadata(project: external_id)

    # TODO: check creds
    :gen_tcp.send(data.socket, authentication_ok())

    {:keep_state, %{data | tenant: external_id}, {:next_event, :internal, :subscribe}}
  end

  def handle_event(:internal, :subscribe, _, %{tenant: tenant} = data) do
    Logger.info("Subscribe to tenant #{tenant}")

    with {:ok, tenant_sup} <- PgEdge.start(tenant),
         {:ok, %{manager: manager, pool: pool}} <-
           PgEdge.subscribe_global(node(tenant_sup), self(), tenant) do
      Process.monitor(manager)
      {:next_state, :idle, %{data | pool: pool, manager: manager}}
    else
      error ->
        Logger.error("Subscribe error: #{inspect(error)}")
        {:keep_state_and_data, {:timeout, 1000, :subscribe}}
    end
  end

  def handle_event(:timeout, :subscribe, _, _) do
    {:keep_state_and_data, {:next_event, :internal, :subscribe}}
  end

  # ignore termination messages
  def handle_event(:info, {:tcp, _, <<?X, 4::32>>}, _, data) do
    Logger.warn("Receive termination")
    :keep_state_and_data
  end

  def handle_event(:info, {:tcp, _, bin}, :idle, data) do
    db_pid =
      data.pool
      |> :poolboy.checkout(true, 60000)

    Process.link(db_pid)
    :ok = Db.call(db_pid, bin)

    {:next_state, :busy, %{data | db_pid: db_pid}}
  end

  def handle_event(:info, {:tcp, _, bin}, :busy, data) do
    Db.call(data.db_pid, bin)

    :keep_state_and_data
  end

  # client closed connection
  def handle_event(_, {:tcp_closed, _}, _, data) do
    Logger.info("tcp soket closed for #{inspect(data.tenant)}")
    {:stop, :normal}
  end

  # linked db_handler went down
  def handle_event(:info, {:EXIT, db_pid, reason}, _, %{db_pid: db_pid} = data) do
    Logger.error("DB handler #{inspect(db_pid)} exited #{inspect(reason)}")
    {:stop, :normal}
  end

  # pool's manager went down
  def handle_event(:info, {:DOWN, _, _, _, reason}, state, data) do
    Logger.error(
      "Manager #{inspect(data.manager)} went down #{inspect(reason)} state #{inspect(state)}"
    )

    case state do
      :idle ->
        {:keep_state_and_data, {:next_event, :internal, :subscribe}}

      :busy ->
        {:stop, :normal}
    end
  end

  # emulate handle_call
  def handle_event({:call, from}, {:client_call, bin, ready?}, _, data) do
    Logger.debug("--> --> bin #{inspect(byte_size(bin))} bytes")

    reply = {:reply, from, :gen_tcp.send(data.socket, bin)}

    if ready? do
      Logger.debug("Client is ready")

      Process.unlink(data.db_pid)
      :poolboy.checkin(data.pool, data.db_pid)
      {:next_state, :idle, %{data | db_pid: nil}, reply}
    else
      Logger.debug("Client is not ready")
      {:keep_state_and_data, reply}
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
end
