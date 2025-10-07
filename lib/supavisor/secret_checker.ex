defmodule Supavisor.SecretChecker do
  @moduledoc false

  use GenServer
  require Logger

  alias Supavisor.{Helpers, Tenants}

  @interval :timer.seconds(15)

  def start_link(args) do
    name = {:via, Registry, {Supavisor.Registry.Tenants, {:secret_checker, args.id}}}
    GenServer.start_link(__MODULE__, args, name: name)
  end

  @spec get_secrets(Supavisor.id()) ::
          {:ok, {method :: atom(), Supavisor.secrets()}} | {:error, :not_started}
  def get_secrets(id) do
    erpc_call_node(id, fn ->
      case Registry.lookup(Supavisor.Registry.Tenants, {:secret_checker, id}) do
        [] ->
          {:error, :not_started}

        [{pid, _}] ->
          GenServer.call(pid, :get_secrets)
      end
    end)
  end

  @spec update_credentials(Supavisor.id(), String.t(), (-> String.t())) ::
          :ok | {:error, :not_started}
  def update_credentials(id, new_user, password_fn) do
    erpc_call_node(id, fn ->
      case Registry.lookup(Supavisor.Registry.Tenants, {:secret_checker, id}) do
        [] ->
          {:error, :not_started}

        [{pid, _}] ->
          GenServer.call(pid, {:update_credentials, new_user, password_fn})
      end
    end)
  end

  def init(args) do
    Logger.debug("SecretChecker: Starting secret checker")
    {{_type, tenant}, user, _mode, db_name, _search_path} = args.id

    state = %{
      id: args.id,
      tenant_external_id: tenant,
      user: user,
      db_name: db_name,
      key: {:secrets, tenant, user},
      ttl: args[:ttl] || :timer.hours(24),
      conn: nil,
      check_ref: nil,
      auth: nil
    }

    Logger.metadata(project: tenant, user: user)
    {:ok, state, {:continue, :init_conn}}
  end

  def handle_continue(:init_conn, state) do
    tenant = Tenants.get_tenant_by_external_id(state.tenant_external_id)

    auth_query_user =
      case tenant.users do
        [u] -> u
        users -> Enum.find(users, fn u -> u.is_manager end)
      end

    if auth_query_user do
      auth =
        tenant
        |> Map.put(:users, [auth_query_user])
        |> Supavisor.build_auth(
          state.db_name,
          :auth_query,
          {:auth_query, fn -> %{} end},
          "Supavisor (auth_query)"
        )

      {:ok, conn} = start_postgrex_connection(auth)
      {:noreply, %{state | conn: conn, auth: auth, check_ref: check()}}
    else
      Logger.info("SecretsChecker terminating: no adequate user found")
      {:noreply, {:stop, :normal}}
    end
  end

  def handle_info(:check, state) do
    check_secrets(state.user, state)
    {:noreply, %{state | check_ref: check()}}
  end

  def handle_info(msg, state) do
    Logger.error("Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  def check(interval \\ @interval),
    do: Process.send_after(self(), :check, interval + jitter())

  def check_secrets(user, %{auth: auth, conn: conn} = state) do
    case Helpers.get_user_secret(conn, auth.auth_query, user) do
      {:ok, secret} ->
        method = if secret.digest == :md5, do: :auth_query_md5, else: :auth_query
        secrets = Map.put(secret, :alias, auth.alias)

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
          value = {:ok, {method, fn -> secrets end}}
          Cachex.put(Supavisor.Cache, state.key, {:cached, value}, expire: :timer.hours(24))
        end

        {:ok, {method, fn -> secret end}}

      other ->
        Logger.error("Failed to get secret: #{inspect(other)}")
    end
  end

  def handle_call(:get_secrets, _from, state) do
    {:reply, check_secrets(state.user, state), state}
  end

  def handle_call({:update_credentials, new_user, password_fn}, _from, state) do
    Logger.info("SecretChecker: changing auth_query user to #{new_user}")

    new_auth = %{
      state.auth
      | user: new_user,
        password: password_fn
    }

    {:ok, new_conn} = start_postgrex_connection(new_auth)

    old_conn = state.conn
    Process.unlink(old_conn)

    Task.start(fn ->
      try do
        GenServer.stop(old_conn, :normal, 5_000)
      catch
        :exit, _ -> Process.exit(old_conn, :kill)
      end
    end)

    Cachex.del(Supavisor.Cache, state.key)

    Logger.info("SecretChecker: Successfully changed auth_query user")
    {:reply, :ok, %{state | auth: new_auth, conn: new_conn}}
  end

  defp start_postgrex_connection(auth) do
    ssl_opts =
      if auth.upstream_ssl and auth.upstream_verify == :peer do
        [
          verify: :verify_peer,
          cacerts: [Helpers.upstream_cert(auth.upstream_tls_ca)],
          server_name_indication: auth.host,
          customize_hostname_check: [{:match_fun, fn _, _ -> true end}]
        ]
      else
        [
          verify: :verify_none
        ]
      end

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
      ssl_opts: ssl_opts
    )
  end

  defp jitter, do: :rand.uniform(div(@interval, 10))

  defp erpc_call_node(id, fun) do
    case Supavisor.get_global_sup(id) do
      nil ->
        {:error, :not_started}

      pid ->
        :erpc.call(node(pid), fun)
    end
  end
end
