defmodule Supavisor.Handlers.Proxy.Handler do
  @moduledoc false

  require Logger

  @behaviour :ranch_protocol
  @behaviour :gen_statem

  alias Supavisor.{
    Helpers,
    Protocol.Server,
    Monitoring.PromEx,
    Handlers.Proxy.Db,
    Handlers.Proxy.Client
  }

  alias Supavisor.HandlerHelpers, as: HH

  @sock_closed [:tcp_closed, :ssl_closed]
  @proto [:tcp, :ssl]

  @impl true
  def start_link(ref, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  @impl true
  def init(_), do: :ignore

  def init(ref, trans, opts) do
    Process.flag(:trap_exit, true)
    Helpers.set_max_heap_size(90)

    {:ok, sock} = :ranch.handshake(ref)
    :ok = trans.setopts(sock, active: true)
    Logger.debug("ClientHandler is: #{inspect(self())}")

    data = %{
      id: nil,
      sock: {:gen_tcp, sock},
      db_sock: {:gen_tcp, nil},
      trans: trans,
      db_pid: nil,
      tenant: nil,
      user: nil,
      pool: nil,
      manager: nil,
      query_start: nil,
      timeout: nil,
      ps: nil,
      ssl: false,
      auth_secrets: nil,
      proxy_type: nil,
      mode: opts.mode,
      stats: %{},
      db_stats: %{},
      idle_timeout: 0,
      db_name: nil,
      last_query: nil,
      heartbeat_interval: 0,
      connection_start: System.monotonic_time(),
      log_level: nil,
      version: Application.spec(:supavisor, :vsn),
      auth: nil,
      nonce: nil,
      server_proof: nil,
      parameter_status: %{},
      app_name: nil,
      peer_ip: Helpers.peer_ip(sock),
      auth: %{},
      backend_key_data: %{}
    }

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :exchange, data)
  end

  @impl true
  def handle_event(e, {:client, _} = msg, state, data) do
    Client.handle_event(e, msg, state, data)
  end

  def handle_event(:timeout = e, msg, state, data) do
    Client.handle_event(e, msg, state, data)
  end

  def handle_event(event, {proto, sock, _payload} = msg, state, %{sock: {_, sock}} = data)
      when proto in @proto do
    Client.handle_event(event, msg, state, data)
  end

  def handle_event(event, {proto, sock, _payload} = msg, state, %{db_sock: {_, sock}} = data)
      when proto in @proto do
    Db.handle_event(event, msg, state, data)
  end

  def handle_event(event, {closed, sock} = msg, state, %{sock: {_, sock}} = data)
      when closed in @sock_closed do
    Client.handle_event(event, msg, state, data)
  end

  def handle_event(event, {closed, sock} = msg, state, %{db_sock: {_, sock}} = data)
      when closed in @sock_closed do
    Db.handle_event(event, msg, state, data)
  end

  def handle_event(type, content, state, data) do
    msg = [
      {"type", type},
      {"content", content},
      {"state", state},
      {"data", data}
    ]

    Logger.debug("ProxyHandler: Undefined msg: #{inspect(msg, pretty: true)}")

    :keep_state_and_data
  end

  @impl true
  def terminate({:shutdown, reason}, state, data) do
    HH.sock_send(data.sock, Server.error_message("XX000", "#{inspect(reason)}"))
    clean_up(data)

    Logger.info(
      "ProxyHandler: Terminating with reason: #{inspect(reason)} when state was #{state}"
    )

    :ok
  end

  def terminate(reason, state, data) do
    clean_up(data)

    Logger.info(
      "ProxyHandler: Terminating with reason: #{inspect(reason)} when state was #{state}"
    )
  end

  ## Internal functions

  @spec clean_up(map()) :: any()
  defp clean_up(data) do
    HH.sock_close(data.sock)
    HH.sock_close(data.db_sock)

    case Registry.lookup(Supavisor.Registry.TenantClients, data.id) do
      clients when clients in [[{self(), []}], []] -> PromEx.remove_metrics(data.id)
      _ -> :ok
    end
  end
end
