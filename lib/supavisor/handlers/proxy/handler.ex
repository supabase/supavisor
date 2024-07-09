defmodule Supavisor.Handlers.Proxy.Handler do
  @moduledoc false

  require Logger

  @behaviour :ranch_protocol
  @behaviour :gen_statem

  alias Supavisor, as: S
  alias Supavisor.DbHandler, as: Db
  alias Supavisor.Handlers.Proxy.Db, as: ProxyDb
  alias Supavisor.Handlers.Proxy.Client, as: ProxyClient
  alias Supavisor.Helpers, as: H
  alias Supavisor.HandlerHelpers, as: HH
  alias Supavisor.{Tenants, ProxyHandlerDb, Monitoring.Telem, Protocol.Client, Protocol.Server}

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
    H.set_max_heap_size(150)

    {:ok, sock} = :ranch.handshake(ref)
    H.peer_ip(sock) |> IO.inspect()
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
      peer_ip: H.peer_ip(sock),
      auth: nil
    }

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :exchange, data)
  end

  @impl true
  def handle_event(:internal, :check_buffer, _, data) do
    ps = Server.encode_parameter_status(data.parameter_status)
    # IO.inspect({111, ps})
    {:keep_state_and_data, {:next_event, :internal, {:client, {:greetings, ps}}}}
  end

  def handle_event(e, {:client, _} = msg, state, data) do
    ProxyClient.handle_event(e, msg, state, data)
  end

  def handle_event(:timeout = e, msg, state, data) do
    ProxyClient.handle_event(e, msg, state, data)
  end

  def handle_event(:info = e, {:parameter_status, _} = msg, state, data) do
    ProxyClient.handle_event(e, msg, state, data)
  end

  def handle_event(event, {proto, sock, _payload} = msg, state, %{sock: {_, sock}} = data)
      when proto in @proto do
    ProxyClient.handle_event(event, msg, state, data)
  end

  def handle_event(event, {proto, sock, _payload} = msg, state, %{db_sock: {_, sock}} = data)
      when proto in @proto do
    ProxyDb.handle_event(event, msg, state, data)
  end

  def handle_event(event, {closed, sock} = msg, state, %{sock: {_, sock}} = data)
      when closed in @sock_closed do
    ProxyClient.handle_event(event, msg, state, data)
  end

  def handle_event(event, {closed, sock} = msg, state, %{db_sock: {_, sock}} = data)
      when closed in @sock_closed do
    ProxyDb.handle_event(event, msg, state, data)
  end
end
