defmodule Supavisor.OpsTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  import ExUnit.CaptureLog
  import Supavisor.TenantsFixtures
  import Supavisor.Asserts, only: [assert_eventually: 1, assert_eventually: 3]

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

  describe "stop_pool/3" do
    setup do
      tenant_fixture(%{external_id: @tenant})
      :ok
    end

    test "stops the pool and leaves the tenant's other pools running" do
      id = start_pool!(pool_id(mode: :transaction))
      other = start_pool!(pool_id(mode: :session))
      sup = Supavisor.get_global_sup(id)
      other_sup = Supavisor.get_global_sup(other)
      assert is_pid(sup) and is_pid(other_sup)

      assert {:ok, :stopped} = Ops.stop_pool(@tenant, sup)
      refute Process.alive?(sup)
      assert Supavisor.get_global_sup(id) == nil
      # The same process: the other pool was neither stopped nor restarted.
      assert Process.alive?(other_sup)
      assert Supavisor.get_global_sup(other) == other_sup
    end

    test "logs the start of the stop and its result" do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)

      log =
        capture_log([level: :info], fn -> assert {:ok, :stopped} = Ops.stop_pool(@tenant, sup) end)

      assert log =~ "stopping, timeout"
      assert log =~ "{:ok, :stopped}"
    end

    test "logs a warning when the pool is not found" do
      log =
        capture_log([level: :warning], fn ->
          assert {:error, :not_found} = Ops.stop_pool(@tenant, self())
        end)

      assert log =~ "pool pid #PID<"
      assert log =~ "not found"
    end

    test "returns :not_found once the pool has stopped" do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      :ok = Supervisor.stop(sup)

      # The registry drops the pool shortly after it exits.
      assert_eventually(fn -> Ops.stop_pool(@tenant, sup) == {:error, :not_found} end)
    end

    test "returns :not_found for a process that is not a pool" do
      assert {:error, :not_found} = Ops.stop_pool(@tenant, self())
    end

    test "does not stop a pool of another tenant" do
      other_tenant = "ops_test_other_tenant"
      tenant_fixture(%{external_id: other_tenant})
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)

      assert {:error, :not_found} = Ops.stop_pool(other_tenant, sup)
      assert Process.alive?(sup)
      assert Supavisor.get_global_sup(id) == sup
    end

    test "stops a pool that is already shutting down" do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)
      # The pool's poolboy GenServer, once suspended, doesn't answer calls, so the
      # Terminator's call to it on shutdown blocks until the supervisor kills the
      # Terminator after its 5s shutdown timeout. That keeps the pool shutting down
      # for ~5s.
      :sys.suspend(Supavisor.get_local_pool(id))
      # Someone else starts stopping the pool. The Terminator stops first and
      # unregisters the pool from :syn, i.e. the pool is now `shutting_down`.
      spawn(fn -> Supervisor.stop(sup) end)
      assert_eventually(10, 100, fn -> Supavisor.get_global_sup(id) == nil end)

      task = Task.async(fn -> Ops.stop_pool(@tenant, sup) end)

      # The supervisor is busy stopping its children, so our stop request (reason
      # :shutdown, unlike the first one's :normal) waits in its mailbox, unhandled.
      assert_eventually(10, 100, fn ->
        {:messages, messages} = Process.info(sup, :messages)
        Enum.any?(messages, &match?({:system, _from, {:terminate, :shutdown}}, &1))
      end)

      # It exits after ~5s without handling it, which ends our wait.
      assert {:ok, :stopped} = Task.await(task, 10_000)
      refute Process.alive?(sup)
    end

    test "returns :stopping when the pool is still shutting down at the timeout" do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)

      # The Terminator's call to the suspended poolboy blocks until the supervisor
      # kills it after its 5s shutdown timeout.
      :sys.suspend(Supavisor.get_local_pool(id))

      assert {:ok, :stopping} = Ops.stop_pool(@tenant, sup, 100)

      # The stop still completes in the background, and the pool is not restarted.
      assert_eventually(10, 1_000, fn ->
        not Process.alive?(sup) and Ops.list_pools_local(@tenant) == []
      end)
    end
  end

  describe "restart_node/1" do
    test "returns :not_found for a node that is not in the cluster" do
      log =
        capture_log([level: :warning], fn ->
          assert {:error, :not_found} = Ops.restart_node("no_such_node")
        end)

      assert log =~ "Restart node no_such_node: not_found"
    end
  end
end
