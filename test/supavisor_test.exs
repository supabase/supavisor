defmodule SupavisorTest do
  use Supavisor.DataCase, async: true

  import Supavisor.Asserts

  alias Supavisor.Errors.{
    WorkerNotFoundError,
    PoolRanchNotFoundError,
    PoolConfigNotFoundError
  }

  @fake_id {{:single, "nonexistent_tenant"}, "user", :transaction, "db", ""}

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
      fake_id = {{:single, "nonexistent_config_tenant"}, "user", :transaction, "db", ""}
      secrets = {:password, fn -> %{user: "user"} end}

      assert {:error, %PoolConfigNotFoundError{id: ^fake_id}} =
               result = Supavisor.start_local_pool(fake_id, secrets, nil)

      assert_valid_error(result)
    end
  end
end
