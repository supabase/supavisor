defmodule Supavisor.Integration.SecretCheckerTest do
  use SupavisorWeb.ConnCase, async: false

  require Supavisor
  alias Postgrex, as: P
  alias Supavisor.Secrets.SASLSecrets
  alias Supavisor.UpstreamAuthentication

  defmodule CrashingSecretChecker do
    use GenServer

    def start(id) do
      name = {:via, Registry, {Supavisor.Registry.Tenants, {:secret_checker, id}}}
      GenServer.start(__MODULE__, nil, name: name)
    end

    @impl true
    def init(nil), do: {:ok, nil}

    @impl true
    def handle_call(:get_secrets, _from, state) do
      exit(:boom)
      {:reply, :unreachable, state}
    end
  end

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant_id = "secret_checker_tenant_#{System.unique_integer([:positive])}"

    {:ok, _tenant} =
      Supavisor.Tenants.create_tenant(%{
        db_database: db_conf[:database],
        db_host: to_string(db_conf[:hostname]),
        db_port: db_conf[:port],
        external_id: tenant_id,
        require_user: false,
        auth_query:
          "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1 AND current_database() = '#{db_conf[:database]}'",
        default_parameter_status: %{"server_version" => "15.0"},
        users: [
          %{
            "db_user" => to_string(db_conf[:username]),
            "db_password" => to_string(db_conf[:password]),
            "pool_size" => 3,
            "mode_type" => "transaction",
            "is_manager" => true
          }
        ]
      })

    %{db_conf: db_conf, tenant_id: tenant_id}
  end

  test "SecretChecker can fetch secrets when pool uses different database", %{
    db_conf: db_conf,
    tenant_id: tenant_id
  } do
    alt_db_name = "supavisor_test_alt_#{System.unique_integer([:positive])}"

    origin =
      start_supervised!(
        {Postgrex,
         hostname: db_conf[:hostname],
         port: db_conf[:port],
         database: db_conf[:database],
         password: db_conf[:password],
         username: db_conf[:username]},
        id: :origin_conn
      )

    P.query!(origin, "CREATE DATABASE #{alt_db_name}", [])

    proxy =
      start_supervised!(
        {Postgrex,
         hostname: db_conf[:hostname],
         port: Application.get_env(:supavisor, :proxy_port_transaction),
         database: alt_db_name,
         password: db_conf[:password],
         username: "#{db_conf[:username]}.#{tenant_id}"},
        id: :proxy_conn
      )

    assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])

    Process.sleep(100)

    pool_id =
      Supavisor.id(
        type: :single,
        tenant: tenant_id,
        user: to_string(db_conf[:username]),
        mode: :transaction,
        db: alt_db_name
      )

    assert {:ok, %Supavisor.ClientAuthentication.ValidationSecrets{} = secrets, _cache} =
             Supavisor.SecretChecker.get_secrets(pool_id)

    assert %{user: _} = secrets.sasl_secrets
  end

  test "fetch_validation_secrets does not hang when SecretChecker exits", %{
    db_conf: db_conf,
    tenant_id: tenant_id
  } do
    tenant = Supavisor.Tenants.get_tenant_by_external_id(tenant_id)
    manager_user = Enum.find(tenant.users, & &1.is_manager)

    id =
      Supavisor.id(
        type: :single,
        tenant: tenant_id,
        user: to_string(db_conf[:username]),
        mode: :transaction,
        db: db_conf[:database]
      )

    # Register a fake sup in :syn so get_global_sup returns a local pid
    fake_sup = spawn_link(fn -> Process.sleep(:infinity) end)
    :syn.register(:tenants, id, fake_sup)

    # Register a GenServer that exits on :get_secrets, simulating the crash
    # that causes the Cachex Courier deadlock without the fix
    {:ok, _} = CrashingSecretChecker.start(id)

    Supavisor.ClientAuthentication.invalidate_local(tenant_id, to_string(db_conf[:username]))

    # Before the fix, the exit would kill the Cachex Courier's spawned task,
    # causing all subsequent Cachex.fetch calls for this key to block forever.
    task =
      Task.async(fn ->
        Supavisor.ClientAuthentication.fetch_validation_secrets(id, tenant, manager_user)
      end)

    assert {:ok, %Supavisor.ClientAuthentication.ValidationSecrets{}} =
             Task.await(task, 5_000)
  end

  describe "upstream auth secrets after a password change" do
    @password "secret_checker_rotation_password"

    setup %{db_conf: db_conf, tenant_id: tenant_id} do
      role = "secret_checker_rotation_#{System.unique_integer([:positive])}"
      origin = start_supervised!({Postgrex, origin_opts(db_conf)}, id: :origin_conn)
      P.query!(origin, "CREATE ROLE #{role} WITH LOGIN PASSWORD '#{@password}'", [])

      on_exit(fn ->
        {:ok, cleanup} = Postgrex.start_link(origin_opts(db_conf))
        Postgrex.query!(cleanup, "DROP ROLE IF EXISTS #{role}", [])
      end)

      pool_id =
        Supavisor.id(
          type: :single,
          tenant: tenant_id,
          user: role,
          mode: :transaction,
          db: db_conf[:database]
        )

      proxy = connect_to_proxy(db_conf, role, tenant_id, :first_client)
      assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])

      assert {:ok, %SASLSecrets{}} = UpstreamAuthentication.get_upstream_auth_secrets(pool_id)

      %{origin: origin, role: role, pool_id: pool_id, proxy: proxy}
    end

    test "are dropped once the role's SCRAM verifier is re-salted", ctx do
      # Same plaintext, but Postgres stores a new salt and keys.
      P.query!(ctx.origin, "ALTER ROLE #{ctx.role} PASSWORD '#{@password}'", [])

      assert {:ok, _secrets, _cache} = Supavisor.SecretChecker.get_secrets(ctx.pool_id)

      assert {:error, :not_found} =
               UpstreamAuthentication.get_upstream_auth_secrets(ctx.pool_id)

      proxy = connect_to_proxy(ctx.db_conf, ctx.role, ctx.tenant_id, :second_client)
      assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])
      assert {:ok, %SASLSecrets{}} = UpstreamAuthentication.get_upstream_auth_secrets(ctx.pool_id)
    end

    test "are dropped for every pool of the role, not only the first to refresh", ctx do
      session_proxy =
        connect_to_proxy(ctx.db_conf, ctx.role, ctx.tenant_id, :session_client, :session)

      assert %P.Result{rows: [[1]]} = P.query!(session_proxy, "SELECT 1", [])

      session_pool_id =
        Supavisor.id(
          type: :single,
          tenant: ctx.tenant_id,
          user: ctx.role,
          mode: :session,
          db: ctx.db_conf[:database]
        )

      assert {:ok, %SASLSecrets{}} =
               UpstreamAuthentication.get_upstream_auth_secrets(session_pool_id)

      P.query!(ctx.origin, "ALTER ROLE #{ctx.role} PASSWORD '#{@password}'", [])

      # The first refresh updates the shared validation cache, so the second one is a no-op.
      assert {:ok, _secrets, :changed} = Supavisor.SecretChecker.get_secrets(ctx.pool_id)
      assert {:ok, _secrets, :noop} = Supavisor.SecretChecker.get_secrets(session_pool_id)

      assert {:error, :not_found} = UpstreamAuthentication.get_upstream_auth_secrets(ctx.pool_id)

      assert {:error, :not_found} =
               UpstreamAuthentication.get_upstream_auth_secrets(session_pool_id)
    end

    test "are kept while the verifier is unchanged", ctx do
      {:ok, before} = UpstreamAuthentication.get_upstream_auth_secrets(ctx.pool_id)

      assert {:ok, _secrets, _cache} = Supavisor.SecretChecker.get_secrets(ctx.pool_id)

      assert {:ok, ^before} = UpstreamAuthentication.get_upstream_auth_secrets(ctx.pool_id)
    end

    test "are kept when only the digest spelling differs", ctx do
      # DbHandler derives secrets with digest "sha-256"; pg_authid says "SCRAM-SHA-256".
      {:ok, client_secrets} = UpstreamAuthentication.get_upstream_auth_secrets(ctx.pool_id)
      derived = %{client_secrets | digest: "sha-256"}
      UpstreamAuthentication.put_upstream_auth_secrets(ctx.pool_id, derived)

      assert {:ok, _secrets, _cache} = Supavisor.SecretChecker.get_secrets(ctx.pool_id)

      assert {:ok, ^derived} = UpstreamAuthentication.get_upstream_auth_secrets(ctx.pool_id)
    end
  end

  defp connect_to_proxy(db_conf, role, tenant_id, id, mode \\ :transaction) do
    start_supervised!(
      {Postgrex,
       hostname: db_conf[:hostname],
       port: Application.get_env(:supavisor, :"proxy_port_#{mode}"),
       database: db_conf[:database],
       password: @password,
       username: "#{role}.#{tenant_id}"},
      id: id
    )
  end

  defp origin_opts(db_conf) do
    [
      hostname: db_conf[:hostname],
      port: db_conf[:port],
      database: db_conf[:database],
      password: db_conf[:password],
      username: db_conf[:username]
    ]
  end
end
