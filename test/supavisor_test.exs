defmodule SupavisorTest do
  use ExUnit.Case, async: true

  require Supavisor

  import ExUnit.CaptureLog
  import Supavisor.Asserts

  alias Supavisor.Errors.{
    WorkerNotFoundError,
    PoolRanchNotFoundError,
    PoolConfigNotFoundError
  }

  defp fake_pool_pid do
    spawn_link(fn -> Process.sleep(:infinity) end)
  end

  defp build_id(tenant, user) do
    Supavisor.id(
      type: :single,
      tenant: tenant,
      user: user,
      mode: :transaction,
      db: "postgres",
      search_path: nil
    )
  end

  @fake_id Supavisor.id(
             type: :single,
             tenant: "nonexistent_tenant",
             user: "user",
             mode: :transaction,
             db: "db",
             search_path: nil
           )

  describe "inspect_id/1" do
    test "key and value are never split across lines" do
      id =
        Supavisor.id(
          type: :single,
          tenant: "some_very_long_tenant_name_that_could_cause_wrapping",
          user: "postgres",
          mode: :session,
          db: "some_very_long_tenant_name_that_could_cause_wrapping",
          search_path: nil
        )

      assert Supavisor.inspect_id(id) == """
             Supavisor.id(
               type: :single,
               tenant: "some_very_long_tenant_name_that_could_cause_wrapping",
               mode: :session,
               user: "postgres",
               db: "some_very_long_tenant_name_that_could_cause_wrapping"
             )\
             """
    end

    test "omits nil values" do
      id =
        Supavisor.id(
          type: :single,
          tenant: "my_tenant",
          user: "postgres",
          mode: :session,
          db: "my_db",
          search_path: nil
        )

      assert Supavisor.inspect_id(id) == """
             Supavisor.id(type: :single, tenant: "my_tenant", mode: :session, user: "postgres", db: "my_db")\
             """
    end

    test "includes search_path when set" do
      id =
        Supavisor.id(
          type: :single,
          tenant: "my_tenant",
          user: "postgres",
          mode: :session,
          db: "my_db",
          search_path: "public"
        )

      assert Supavisor.inspect_id(id) ==
               """
               Supavisor.id(type: :single, tenant: "my_tenant", mode: :session, user: "postgres", db: "my_db", search_path: "public")\
               """
    end

    test "falls back to inspect for invalid ids" do
      assert Supavisor.inspect_id(:not_an_id) == ":not_an_id"
    end
  end

  describe "stop/1" do
    test "returns WorkerNotFoundError for nonexistent id" do
      assert {:error, %WorkerNotFoundError{id: @fake_id}} =
               result = Supavisor.stop(@fake_id)

      assert_valid_error(result)
    end
  end

  describe "get_local_workers/1" do
    test "returns WorkerNotFoundError for nonexistent id" do
      assert {:error, %WorkerNotFoundError{id: @fake_id}} =
               result = Supavisor.get_local_workers(@fake_id)

      assert_valid_error(result)
    end
  end

  describe "get_pool_ranch/1" do
    test "returns PoolRanchNotFoundError for nonexistent id" do
      assert {:error, %PoolRanchNotFoundError{id: @fake_id}} =
               result = Supavisor.get_pool_ranch(@fake_id)

      assert_valid_error(result)
    end
  end

  describe "start_local_pool/3" do
    test "returns PoolConfigNotFoundError when tenant config not found" do
      secrets = %{user: "user"}

      assert {:error, %PoolConfigNotFoundError{id: @fake_id}} =
               result = Supavisor.start_local_pool(@fake_id, secrets, nil)

      assert_valid_error(result)
    end

    test "sets project/user logger metadata at :info level" do
      secrets = %{user: "user"}

      log =
        capture_log([level: :info], fn -> Supavisor.start_local_pool(@fake_id, secrets, nil) end)

      assert log =~ "Starting pool(s) for"
      assert log =~ "project=nonexistent_tenant"
      assert log =~ "user=user"
    end
  end

  describe "join_tenant_pool/2" do
    test "no pools joined before anything joins" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"

      assert [] == Supavisor.tenant_pools(tenant, user)
    end

    test "joined pool shows up after joining" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid = fake_pool_pid()

      :ok = Supavisor.join_tenant_pool(build_id(tenant, user), pid)

      assert [pid] == Supavisor.tenant_pools(tenant, user)
    end

    test "joined pid drops out once it dies" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid = fake_pool_pid()

      :ok = Supavisor.join_tenant_pool(build_id(tenant, user), pid)
      assert [pid] == Supavisor.tenant_pools(tenant, user)

      Process.unlink(pid)
      Process.exit(pid, :kill)

      assert_eventually(fn -> Supavisor.tenant_pools(tenant, user) == [] end)
    end

    test "other joined pids remain while at least one is alive" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid1 = fake_pool_pid()
      pid2 = fake_pool_pid()
      id = build_id(tenant, user)

      :ok = Supavisor.join_tenant_pool(id, pid1)
      :ok = Supavisor.join_tenant_pool(id, pid2)

      Process.unlink(pid1)
      Process.exit(pid1, :kill)

      assert_eventually(fn -> Supavisor.tenant_pools(tenant, user) == [pid2] end)
    end

    test "returns and logs an error if the pool is not alive" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid = spawn(fn -> :ok end)
      assert_eventually(fn -> not Process.alive?(pid) end)

      {:error, :not_alive} =
        Supavisor.join_tenant_pool(build_id(tenant, user), pid)

      assert [] == Supavisor.tenant_pools(tenant, user)
    end
  end

  describe "tenant_pools/2" do
    test "empty when nothing has joined" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"

      assert [] == Supavisor.tenant_pools(tenant, user)
    end

    test "lists every pid joined for {tenant, db_user}" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid1 = fake_pool_pid()
      pid2 = fake_pool_pid()
      id = build_id(tenant, user)

      :ok = Supavisor.join_tenant_pool(id, pid1)
      :ok = Supavisor.join_tenant_pool(id, pid2)

      assert Enum.sort([pid1, pid2]) ==
               Enum.sort(Supavisor.tenant_pools(tenant, user))
    end
  end
end
