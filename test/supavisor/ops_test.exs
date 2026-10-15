defmodule Supavisor.OpsTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  import Supavisor.TenantsFixtures
  import Supavisor.Asserts, only: [assert_eventually: 1]

  alias Supavisor.Ops
  alias Supavisor.Support.Cluster

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

    test "returns no pools for a tenant that has none" do
      assert %{pools: [], errors: %{}} = Ops.list_pools("tenant_without_pools")
    end

    test "lists a started pool with id, node, host and port" do
      id = start_pool!(pool_id([]))

      assert %{pools: [pool], errors: %{}} = Ops.list_pools(@tenant)
      assert pool.id == id
      assert pool.node == node()
      assert pool.host == "localhost"
      assert pool.port == 6432
    end

    test "reports the client count and backend connection counts" do
      id = start_pool!(pool_id([]))
      subscribe_clients(id, 2)

      # The warm worker (min pool size 1) connects asynchronously, so wait for it.
      assert_eventually(fn ->
        %{pools: [pool]} = Ops.list_pools(@tenant)
        pool.clients == 2 and pool.connections == %{idle: 1, checked_out: 0}
      end)
    end

    test "lists every pool of the tenant" do
      transaction = start_pool!(pool_id(mode: :transaction))
      session = start_pool!(pool_id(mode: :session))

      assert %{pools: pools, errors: %{}} = Ops.list_pools(@tenant)
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

      assert %{pools: [pool]} = Ops.list_pools(@tenant)
      assert pool.id == mine

      assert %{pools: [pool]} = Ops.list_pools(other)
      assert pool.id == theirs
    end

    test "records a node whose call fails under errors" do
      # Make the per-node call fail; :erpc.multicall then returns an error for that
      # node, which list_pools/1 must collect under :errors rather than raise.
      :meck.new(Supavisor.Ops, [:passthrough, :no_link])
      on_exit(fn -> :meck.unload(Supavisor.Ops) end)
      :meck.expect(Supavisor.Ops, :list_pools_local, fn _tenant -> raise "boom" end)

      assert %{pools: [], errors: errors} = Supavisor.Ops.list_pools(@tenant)
      assert Map.has_key?(errors, node())
    end
  end

  describe "across a cluster" do
    @describetag cluster: true

    # A committed (pre-seeded) tenant the peer node can read over its own DB
    # connection; see priv/repo/seeds_after_migration.exs.
    @cluster_tenant "cluster_pool_tenant_1"

    setup do
      {:ok, peer, peer_node} = Cluster.start_node()
      true = Node.connect(peer_node)
      %{peer: peer, peer_node: peer_node}
    end

    # Starts a distinct pool on this node and on the peer, both for @cluster_tenant.
    defp start_pool_on_both(peer) do
      local_id = pool_id(@cluster_tenant, db: "supavisor_test")
      peer_id = pool_id(@cluster_tenant, db: "postgres")

      {:ok, _} = Supavisor.start(local_id, @secret)
      on_exit(fn -> Supavisor.stop(local_id) end)
      {:ok, _} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [peer_id, @secret])

      {local_id, peer_id}
    end

    test "list_pools/1 aggregates pools from every node", %{peer: peer, peer_node: peer_node} do
      {local_id, peer_id} = start_pool_on_both(peer)

      assert_eventually(fn ->
        %{pools: pools, errors: errors} = Ops.list_pools(@cluster_tenant)

        errors == %{} and
          Enum.any?(pools, &(&1.id == local_id and &1.node == node())) and
          Enum.any?(pools, &(&1.id == peer_id and &1.node == peer_node))
      end)
    end

    test "list_pools_local/1 returns only this node's pools", %{peer: peer} do
      {local_id, peer_id} = start_pool_on_both(peer)

      # Wait until the peer pool is visible cluster-wide, so we know it started.
      assert_eventually(fn ->
        Enum.any?(Ops.list_pools(@cluster_tenant).pools, &(&1.id == peer_id))
      end)

      assert [local] = Ops.list_pools_local(@cluster_tenant)
      assert local.id == local_id
      assert local.node == node()
    end

    test "counts a client that enters through another node and is proxied", %{
      peer: peer,
      peer_node: peer_node
    } do
      db_conf = Application.get_env(:supavisor, Supavisor.Repo)

      # Pool is owned by the peer; the client enters through this node's proxy and
      # is proxied to the peer, where it must be counted.
      id = pool_id(@cluster_tenant, db: db_conf[:database])
      {:ok, _} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [id, @secret])

      assert_eventually(fn ->
        Enum.any?(Ops.list_pools(@cluster_tenant).pools, &(&1.id == id and &1.node == peer_node))
      end)

      {:ok, client} =
        Postgrex.start_link(
          hostname: db_conf[:hostname],
          port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
          database: db_conf[:database],
          password: db_conf[:password],
          username: "#{db_conf[:username]}.#{@cluster_tenant}"
        )

      assert %Postgrex.Result{rows: [[1]]} = Postgrex.query!(client, "SELECT 1", [])

      assert_eventually(fn ->
        pool = Enum.find(Ops.list_pools(@cluster_tenant).pools, &(&1.id == id))
        match?(%{clients: 1}, pool)
      end)

      # A direct (owner-side) subscriber on the peer adds to the same count.
      local_sub = :peer.call(peer, :erlang, :spawn, [:timer, :sleep, [:infinity]])
      {:ok, _} = :peer.call(peer, Supavisor, :subscribe, [id, local_sub])

      assert_eventually(fn ->
        pool = Enum.find(Ops.list_pools(@cluster_tenant).pools, &(&1.id == id))
        match?(%{clients: 2}, pool)
      end)
    end
  end
end
