defmodule Supavisor.SecretChecker do
  @moduledoc false

  use GenServer
  require Logger

  alias Supavisor.Helpers

  @interval :timer.seconds(15)

  def start_link(args) do
    name = {:via, Registry, {Supavisor.Registry.Tenants, {:secret_checker, args.id}}}

    GenServer.start_link(__MODULE__, args, name: name)
  end

  def init(args) do
    Logger.debug("SecretChecker: Starting secret checker")
    tenant = Supavisor.tenant(args.id)

    [%{auth: auth, user: user} | _] =
      Enum.filter(args.replicas, fn e -> e.replica_type == :write end)

    state = %{
      tenant: tenant,
      auth: auth,
      user: user,
      key: {:secrets, tenant, user},
      ttl: args[:ttl] || :timer.hours(24),
      conn: nil,
      check_ref: check()
    }

    Logger.metadata(project: tenant, user: user)
    {:ok, state, {:continue, :init_conn}}
  end

  def handle_continue(:init_conn, %{auth: auth} = state) do
    ssl_opts =
      if auth.upstream_ssl and auth.upstream_verify == "peer" do
        [
          {:verify, :verify_peer},
          {:cacerts, [Helpers.upstream_cert(auth.upstream_tls_ca)]},
          {:server_name_indication, auth.host},
          {:customize_hostname_check, [{:match_fun, fn _, _ -> true end}]}
        ]
      end

    {:ok, conn} =
      Postgrex.start_link(
        hostname: auth.host,
        port: auth.port,
        database: auth.database,
        password: auth.password.(),
        username: auth.user,
        parameters: [application_name: "Supavisor auth_query"],
        ssl: auth.upstream_ssl,
        socket_options: [
          auth.ip_version
        ],
        queue_target: 1_000,
        queue_interval: 5_000,
        ssl_opts: ssl_opts || []
      )

    # kill the postgrex connection if the current process exits unexpectedly
    Process.link(conn)
    {:noreply, %{state | conn: conn}}
  end

  def handle_info(:check, state) do
    Logger.debug("Checking secrets")
    check_secrets(state)
    Logger.debug("Secrets checked")
    {:noreply, %{state | check_ref: check()}}
  end

  def handle_info(msg, state) do
    Logger.error("Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  def terminate(_, state) do
    :gen_statem.stop(state.conn)
    :ok
  end

  def check(interval \\ @interval),
    do: Process.send_after(self(), :check, interval)

  def check_secrets(%{auth: auth, user: user, conn: conn} = state) do
    case Helpers.get_user_secret(conn, auth.auth_query, user) do
      {:ok, secret} ->
        method = if secret.digest == :md5, do: :auth_query_md5, else: :auth_query
        secrets = Map.put(secret, :alias, auth.alias)
        value = {:ok, {method, fn -> secrets end}}

        update_cache =
          case Cachex.get(Supavisor.Cache, state.key) do
            {:ok, {:cached, {_, {old_method, old_secrets}}}} ->
              method != old_method or secrets != old_secrets.()

            other ->
              Logger.error("Failed to get cache: #{inspect(other)}")
              true
          end

        if update_cache do
          Logger.info("Secrets changed or not present, updating cache")
          Cachex.put(Supavisor.Cache, state.key, {:cached, value}, expire: :timer.hours(24))
        end

      other ->
        Logger.error("Failed to get secret: #{inspect(other)}")
    end
  end
end
