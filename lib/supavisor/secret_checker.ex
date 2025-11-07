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
    tenant = Supavisor.tenant(args.id)
    {{_type, _tenant}, pool_user, _mode, _db_name, _search_path} = args.id
    auth = Supavisor.Manager.get_auth(args.id)

    state = %{
      tenant: tenant,
      auth: auth,
      user: pool_user,
      ttl: :timer.hours(24),
      conn: nil,
      check_ref: check()
    }

    Logger.metadata(project: tenant, user: pool_user)
    {:ok, state, {:continue, :init_conn}}
  end

  def handle_continue(:init_conn, %{auth: auth} = state) do
    {:ok, conn} = start_postgrex_connection(auth)
    # kill the postgrex connection if the current process exits unexpectedly
    Process.link(conn)
    {:noreply, %{state | conn: conn}}
  end

  def handle_info(:check, state) do
    check_secrets(state.user, state)
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
    do: Process.send_after(self(), :check, interval + jitter())

  def check_secrets(user, %{auth: auth, conn: conn} = state) do
    case Helpers.get_user_secret(conn, auth.auth_query, user) do
      {:ok, secret} ->
        method = if secret.digest == :md5, do: :auth_query_md5, else: :auth_query
        secrets = Map.put(secret, :alias, auth.alias)

        update_cache =
          case Supavisor.SecretCache.get_validation_secrets(state.tenant, state.user) do
            {:ok, {old_method, old_secrets_fn}} ->
              method != old_method or
                Map.delete(secrets, :client_key) != Map.delete(old_secrets_fn.(), :client_key)

            _other ->
              true
          end

        if update_cache do
          Logger.info("Secrets changed or not present, updating cache")

          Supavisor.SecretCache.put_validation_secrets(state.tenant, state.user, method, fn ->
            secrets
          end)
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

    # Clear the secrets cache for this tenant/user
    tenant = state.tenant
    user = state.user
    Cachex.del(Supavisor.Cache, {:secrets, tenant, user})

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
      parameters: [application_name: "Supavisor (auth_query)"],
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
