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

  describe "pools_count_global/2-4" do
    test "counts pools locally" do
      tenant = "pools_count_test_#{System.unique_integer([:positive])}"
      user = "user1"

      for mode <- [:transaction, :session] do
        id = Supavisor.id(type: :single, tenant: tenant, user: user, mode: mode, db: "postgres")
        {:ok, _} = Registry.register(Supavisor.Registry.Tenants, {:manager, id}, nil)
      end

      assert Supavisor.pools_count_global(tenant, user) == 2
    end

    test "returns 0 if there're no pools" do
      assert Supavisor.pools_count_global("nonexistent_tenant", "nonexistent_user") == 0
    end

    test "count pools locally and logs an error on RPC failure" do
      tenant = "pools_count_test_#{System.unique_integer([:positive])}"
      user = "user1"
      id = Supavisor.id(type: :single, tenant: tenant, user: user, mode: :session, db: "postgres")
      {:ok, _} = Registry.register(Supavisor.Registry.Tenants, {:manager, id}, nil)

      assert capture_log(fn ->
               assert Supavisor.pools_count_global(tenant, user, :infinity, [node(), :nonexistent]) ==
                        1
             end) =~ ~r"Counting pools failure.*(nonexistent)"
    end
  end
end
