defmodule Supavisor.OpsTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  import Supavisor.TenantsFixtures

  alias Supavisor.Ops

  @tenant "ops_test_tenant"
  @secret %Supavisor.Secrets.PasswordSecrets{user: "postgres", password: "postgres"}

  defp pool_id(tenant \\ @tenant, opts) do
    Supavisor.id(
      type: :single,
      tenant: tenant,
      user: "postgres",
      mode: opts[:mode] || :transaction,
      db: opts[:db] || "supavisor_test",
      search_path: nil
    )
  end

  defp start_pool!(id) do
    {:ok, _pid} = Supavisor.start(id, @secret)
    on_exit(fn -> Supavisor.stop(id) end)
    id
  end

  # Subscribes `n` throwaway client pids to the pool's manager, bumping its client
  # count without opening real connections. The pids are linked to the test process
  # so they die with it.
  defp subscribe_clients(id, n) do
    for _ <- 1..n do
      pid = spawn_link(fn -> Process.sleep(:infinity) end)
      {:ok, _} = Supavisor.subscribe(id, pid)
      pid
    end
  end

  describe "list_pools/1" do
    setup do
      tenant_fixture(%{external_id: @tenant})
      :ok
    end

    test "returns an error for a tenant that does not exist" do
      assert {:error, :tenant_not_found} = Ops.list_pools("no_such_tenant")
    end

    test "returns no pools for a tenant without running pools" do
      assert {:ok, %{pools: [], errors: %{}}} = Ops.list_pools(@tenant)
    end

    test "lists a started pool with its supervisor, node and database" do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)

      assert {:ok, %{pools: [pool], errors: %{}}} = Ops.list_pools(@tenant)
      assert pool.id == id
      assert pool.pid == sup
      assert pool.pid_label == inspect(sup)
      assert pool.status == :active
      assert pool.node == node()
      assert pool.db_host == "localhost"
      assert pool.db_port == 6432
    end

    test "reports the client count and database connection counts" do
      id = start_pool!(pool_id([]))
      subscribe_clients(id, 2)

      assert {:ok, %{pools: [pool]}} = Ops.list_pools(@tenant)
      assert pool.clients == 2
      assert pool.db_connections == %{idle: 1, checked_out: 0}
    end

    test "marks a pool that is no longer registered as shutting down" do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)
      on_exit(fn -> if Process.alive?(sup), do: Supervisor.stop(sup) end)

      # What the pool's Terminator does first when the pool starts shutting down.
      :ok = :syn.unregister(:tenants, id)

      assert {:ok, %{pools: [pool]}} = Ops.list_pools(@tenant)
      assert pool.pid == sup
      assert pool.status == :shutting_down
    end

    test "lists every pool of the tenant" do
      transaction = start_pool!(pool_id(mode: :transaction))
      session = start_pool!(pool_id(mode: :session))

      assert {:ok, %{pools: pools, errors: %{}}} = Ops.list_pools(@tenant)
      ids = Enum.map(pools, & &1.id)

      assert transaction in ids
      assert session in ids
      assert length(pools) == 2
    end

    test "does not mix pools between tenants" do
      other = "ops_test_other_tenant"
      tenant_fixture(%{external_id: other})

      mine = start_pool!(pool_id([]))
      theirs = start_pool!(pool_id(other, []))

      assert {:ok, %{pools: [pool]}} = Ops.list_pools(@tenant)
      assert pool.id == mine

      assert {:ok, %{pools: [pool]}} = Ops.list_pools(other)
      assert pool.id == theirs
    end

    test "records a node whose call fails under errors" do
      # Make the per-node call fail; :erpc.multicall then returns an error for that
      # node, which list_pools/1 must collect under :errors rather than raise.
      :meck.new(Supavisor.Ops, [:passthrough, :no_link])
      on_exit(fn -> :meck.unload(Supavisor.Ops) end)
      :meck.expect(Supavisor.Ops, :list_pools_local, fn _tenant -> raise "boom" end)

      assert {:ok, %{pools: [], errors: errors}} = Supavisor.Ops.list_pools(@tenant)

      assert [{node, {:error, {:exception, %RuntimeError{message: "boom"}, _stacktrace}}}] =
               Map.to_list(errors)

      assert node == node()
    end
  end
end
