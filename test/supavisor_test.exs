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

  describe "register_tenant_db_user_for_pool/3 and tenant_db_user_registered?/2" do
    test "registered? is false before anything joins" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"

      refute Supavisor.tenant_db_user_registered?(tenant, user)
    end

    test "registered? is true after joining a pool pid" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"

      :ok = Supavisor.register_tenant_db_user_for_pool(tenant, user, fake_pool_pid())

      assert Supavisor.tenant_db_user_registered?(tenant, user)
    end

    test "registered? goes back to false once the joined pid dies" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid = fake_pool_pid()

      :ok = Supavisor.register_tenant_db_user_for_pool(tenant, user, pid)
      assert Supavisor.tenant_db_user_registered?(tenant, user)

      Process.unlink(pid)
      Process.exit(pid, :kill)

      refute_eventually(fn -> Supavisor.tenant_db_user_registered?(tenant, user) end)
    end

    test "registered? stays true while at least one joined pid is alive" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid1 = fake_pool_pid()
      pid2 = fake_pool_pid()

      :ok = Supavisor.register_tenant_db_user_for_pool(tenant, user, pid1)
      :ok = Supavisor.register_tenant_db_user_for_pool(tenant, user, pid2)

      Process.unlink(pid1)
      Process.exit(pid1, :kill)

      assert_eventually(fn -> Supavisor.tenant_db_user_registered?(tenant, user) end)
    end

    test "register return and logs an error if the pool is not alive" do
      tenant = "syn_pg_test_#{System.unique_integer([:positive])}"
      user = "user1"
      pid = spawn(fn -> :ok end)
      assert_eventually(fn -> not Process.alive?(pid) end)

      {:error, :not_alive} =
        Supavisor.register_tenant_db_user_for_pool(tenant, user, pid)

      refute Supavisor.tenant_db_user_registered?(tenant, user)
    end
  end
end
