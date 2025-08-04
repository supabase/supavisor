defmodule Supavisor.Integration.ClusterPoolingTest do
  use Supavisor.DataCase, async: false

  require Logger

  alias Postgrex, as: P
  alias Supavisor.Support.Cluster

  @tag cluster: true
  test "nodes start unclustered then cluster and pools work across all nodes" do
    db_conf = Application.get_env(:supavisor, Repo)

    {:ok, peer1, node1} = Cluster.start_node_unclustered(:test_node_1, 1)
    {:ok, peer2, node2} = Cluster.start_node_unclustered(:test_node_2, 2)

    # Verify nodes are NOT clustered initially
    refute node1 in Node.list(:connected)
    refute node2 in Node.list(:connected)

    nodes = [
      {:main, Application.get_env(:supavisor, :proxy_port_transaction)},
      {:node1, get_proxy_port(peer1)},
      {:node2, get_proxy_port(peer2)}
    ]

    connection_tasks =
      for i <- 1..10, {node_name, port} <- nodes do
        Task.async(fn ->
          {:ok, proxy} =
            Postgrex.start_link(
              hostname: db_conf[:hostname],
              port: port,
              database: db_conf[:database],
              password: db_conf[:password],
              username: db_conf[:username] <> ".cluster_pool_tenant_#{i}"
            )

          {i, node_name, proxy}
        end)
      end

    connections = Task.await_many(connection_tasks, 10_000)

    for {_i, _node_name, proxy} <- connections do
      assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])
    end

    # Check that pools exist on each node independently (before clustering)
    for i <- 1..10 do
      tenant_key = tenant_key("cluster_pool_tenant_#{i}", db_conf)

      p0 = :syn.lookup(:tenants, tenant_key)
      p1 = :peer.call(peer1, :syn, :lookup, [:tenants, tenant_key])
      p2 = :peer.call(peer2, :syn, :lookup, [:tenants, tenant_key])

      assert MapSet.new([p0, p1, p2]) |> MapSet.size() == 3
    end

    # Manually connect the nodes (simulating cluster formation)
    assert true = Node.connect(node1)
    assert true = Node.connect(node2)

    # Give some time for `:syn` conflict resolution
    :timer.sleep(2500)

    # Check pool distribution after clustering - pools should be consolidated
    for i <- 1..10 do
      tenant_key = tenant_key("cluster_pool_tenant_#{i}", db_conf)

      p0 = :syn.lookup(:tenants, tenant_key)
      p1 = :peer.call(peer1, :syn, :lookup, [:tenants, tenant_key])
      p2 = :peer.call(peer2, :syn, :lookup, [:tenants, tenant_key])

      assert MapSet.new([p0, p1, p2]) |> MapSet.size() == 1
    end

    # Test that all pools work across all nodes after clustering
    for {_i, _node_name, proxy} <- connections do
      P.query!(proxy, "SELECT 1", [])
    end

    # Kill one node and verify pools still work in the others
    :peer.stop(peer1)
    :timer.sleep(1000)

    for {_i, node_name, proxy} <- connections, node_name != :node1 do
      P.query!(proxy, "SELECT 1", [])
    end

    # Cleanup all connections
    for {_, _node_name, proxy} <- connections do
      GenServer.stop(proxy)
    end
  end

  defp get_proxy_port(peer_pid) do
    :peer.call(peer_pid, Application, :get_env, [:supavisor, :proxy_port_transaction])
  end

  defp tenant_key(tenant_name, db_conf) do
    {{:single, tenant_name}, db_conf[:username], :transaction, db_conf[:database], nil}
  end
end
