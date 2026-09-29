defmodule Supavisor.Integration.ClusterProxyTest do
  # Not in the SQL sandbox, so that the cluster is visible to the peer
  use ExUnit.Case, async: false

  require Supavisor

  import Supavisor.Asserts

  alias Postgrex, as: P
  alias Supavisor.Support.Cluster
  alias Supavisor.Tenants

  @moduletag cluster: true

  @peer_name :cluster_proxy_peer
  @peer_node :"cluster_proxy_peer@127.0.0.1"

  test "proxies cluster clients to a pool on another node" do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    {:ok, _peer, @peer_node} = Cluster.start_node(@peer_name)
    true = Node.connect(@peer_node)
    assert_eventually(10, 500, fn -> @peer_node in Supavisor.accepting_nodes() end)

    cluster_alias =
      1..100
      |> Enum.map(&"cluster_proxy_#{&1}")
      |> Enum.find(&(Supavisor.determine_node(id(&1, db_conf), nil) == @peer_node))

    {:ok, cluster} =
      Tenants.create_cluster(%{
        active: true,
        alias: cluster_alias,
        cluster_tenants: [
          %{
            type: "write",
            cluster_alias: cluster_alias,
            tenant_external_id: "cluster_pool_tenant_1",
            active: true
          }
        ]
      })

    on_exit(fn ->
      {:ok, _} = Tenants.delete_cluster(cluster)
      Supavisor.del_all_cache(cluster_alias)
    end)

    {:ok, proxy} =
      start_supervised(
        {P,
         hostname: db_conf[:hostname],
         port: Application.get_env(:supavisor, :proxy_port_transaction),
         database: db_conf[:database],
         password: db_conf[:password],
         username: db_conf[:username] <> ".cluster." <> cluster_alias}
      )

    assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])
    assert node(Supavisor.get_global_sup(id(cluster_alias, db_conf))) == @peer_node
  end

  defp id(cluster_alias, db_conf) do
    Supavisor.id(
      type: :cluster,
      tenant: cluster_alias,
      user: db_conf[:username],
      mode: :transaction,
      db: db_conf[:database]
    )
  end
end
