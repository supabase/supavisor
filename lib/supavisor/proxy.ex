defmodule Supavisor.Proxy do
  @moduledoc false

  require Logger

  @behaviour :ranch_protocol
  @behaviour :gen_statem

  alias Supavisor, as: S
  alias Supavisor.DbHandler, as: Db
  alias Supavisor.ProxyHandlerDb, as: ProxyDb
  alias Supavisor.ProxyHandler, as: ProxyClient
  alias Supavisor.Helpers, as: H
  alias Supavisor.HandlerHelpers, as: HH
  alias Supavisor.{Tenants, ProxyHandlerDb, Monitoring.Telem, Protocol.Client, Protocol.Server}

  @sock_closed [:tcp_closed, :ssl_closed]
  @proto [:tcp, :ssl]

  @impl true
  def start_link(ref, _sock, transport, opts) do
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
      parameter_status: %{}
    }

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :exchange, data)
  end

  @impl true
  def handle_event(:internal, :subscribe, _, data) do
    {_, secrets} = data.auth_secrets

    auth = %{
      application_name: "Supavisor",
      database: "postgres",
      host: 'localhost',
      ip_version: :inet,
      method: :auth_query,
      password: "nil",
      port: 6433,
      require_user: false,
      secrets: secrets,
      upstream_ssl: false,
      upstream_tls_ca: nil,
      upstream_verify: nil,
      user: "postgres"
    }

    Logger.debug("Try to connect to DB")

    sock_opts = [
      :binary,
      {:packet, :raw},
      {:active, true},
      {:nodelay, true},
      auth.ip_version
    ]

    case :gen_tcp.connect(auth.host, auth.port, sock_opts) do
      {:ok, sock} ->
        Logger.debug("DbHandler: auth #{inspect(auth, pretty: true)}")

        case ProxyDb.try_ssl_handshake({:gen_tcp, sock}, auth) do
          {:ok, sock} ->
            case ProxyDb.send_startup(sock, auth) do
              :ok ->
                # :ok = activate(sock)
                {:next_state, :db_authentication, %{data | db_sock: sock, auth: auth}}

              {:error, reason} ->
                Logger.error("DbHandler: Send startup error #{inspect(reason)}")
                {:stop, {:shutdown, :startup_error}}
            end

          {:error, error} ->
            Logger.error("DbHandler: Handshake error #{inspect(error)}")
            {:stop, {:shutdown, :handshake_error}}
        end

      other ->
        Logger.error(
          "DbHandler: Connection failed #{inspect(other)} to #{inspect(auth.host)}:#{inspect(auth.port)}"
        )

        {:stop, {:shutdown, :connection_failed}}
    end
  end

  def handle_event(:internal, :check_buffer, _, data) do
    ps = Server.encode_parameter_status(data.parameter_status)
    IO.inspect({111, ps})
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  def handle_event(:internal = e, msg, state, data) do
    ProxyClient.handle_event(e, msg, state, data)
  end

  def handle_event(:timeout = e, msg, state, data) do
    ProxyClient.handle_event(e, msg, state, data)
  end

  def handle_event(:info = e, {:parameter_status, _} = msg, state, data) do
    ProxyClient.handle_event(e, msg, state, data)
  end

  def handle_event(
        event,
        {:tcp, sock, _payload} = msg,
        state,
        %{sock: {_, client}, db_sock: {_, db}} = data
      ) do
    mod =
      case sock do
        ^client -> ProxyClient
        ^db -> ProxyDb
      end

    apply(mod, :handle_event, [event, msg, state, data])
  end

  def handle_event(
        event,
        {closed, sock} = msg,
        state,
        %{sock: {_, client}, db_sock: {_, db}} = data
      )
      when closed in @sock_closed do
    mod =
      case sock do
        ^client -> ProxyClient
        ^db -> ProxyDb
      end

    apply(mod, :handle_event, [event, msg, state, data])
  end
end
