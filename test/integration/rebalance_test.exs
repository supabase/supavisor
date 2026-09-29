defmodule Supavisor.Integration.RebalanceTest do
  use SupavisorWeb.ConnCase, async: false

  require Supavisor

  import Supavisor.Asserts

  alias Postgrex, as: P
  alias Supavisor.Support.Cluster
  alias Supavisor.Tenants

  @moduletag cluster: true

  @tenants for i <- 1..10, do: "cluster_pool_tenant_#{i}"
  @peer_name :rebalance_peer
  @peer_node :"rebalance_peer@127.0.0.1"
  # The only node in this zone is the peer, see `Supavisor.Support.Cluster`
  @peer_zone "ap-southeast-1c"

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    for tenant <- @tenants, sup = Supavisor.get_global_sup(id(tenant, db_conf)) do
      Supervisor.stop(sup)
    end

    # Hashing alone places this tenant on this node, so only its availability
    # zone sends it to the peer
    zoned_tenant =
      Enum.find(@tenants, &(:erlang.phash2(&1, 2) == index_of(node())))

    {:ok, _} =
      zoned_tenant
      |> Tenants.get_tenant_by_external_id()
      |> Tenants.update_tenant(%{availability_zone: @peer_zone})

    on_exit(fn -> Supavisor.del_all_cache(zoned_tenant) end)

    proxies = Map.new(@tenants, &{&1, start_proxy(&1, db_conf)})

    for {tenant, proxy} <- proxies do
      assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])
      assert node(Supavisor.get_global_sup(id(tenant, db_conf))) == node()
    end

    sups = Map.new(@tenants, &{&1, Supavisor.get_global_sup(id(&1, db_conf))})

    {:ok, _peer, @peer_node} = Cluster.start_node(@peer_name)
    true = Node.connect(@peer_node)

    assert_eventually(10, 500, fn ->
      @peer_node in Supavisor.accepting_nodes() and
        Supavisor.determine_node(id(zoned_tenant, db_conf), @peer_zone) == @peer_node
    end)

    moved =
      Enum.filter(@tenants, fn tenant ->
        tenant == zoned_tenant or :erlang.phash2(tenant, 2) == index_of(@peer_node)
      end)

    assert zoned_tenant in moved
    assert length(moved) < length(@tenants)

    %{db_conf: db_conf, proxies: proxies, sups: sups, moved: moved}
  end

  test "dry run lists the pools to move without moving them", %{
    conn: conn,
    db_conf: db_conf,
    sups: sups,
    moved: moved
  } do
    response =
      conn
      |> put_req_header("authorization", "Bearer " <> gen_token())
      |> put_req_header("content-type", "application/json")
      |> post(~p"/api/rebalance", Jason.encode!(%{dry_run: true}))
      |> json_response(200)
      |> assert_schema("Rebalance")

    assert response.errors == %{}

    moves =
      for move <- response.moves, move.tenant in @tenants, do: Map.from_struct(move)

    assert Enum.sort_by(moves, & &1.tenant) ==
             for(
               tenant <- Enum.sort(moved),
               do: %{
                 tenant: tenant,
                 user: db_conf[:username],
                 mode: "transaction",
                 database: db_conf[:database],
                 from_node: to_string(node()),
                 to_node: to_string(@peer_node)
               }
             )

    for tenant <- @tenants do
      assert Supavisor.get_global_sup(id(tenant, db_conf)) == sups[tenant]
    end
  end

  test "moves pools to the node they would be started on now", %{
    db_conf: db_conf,
    proxies: proxies,
    sups: sups,
    moved: moved
  } do
    result = Supavisor.rebalance()

    assert {:ok, []} = result[@peer_node]
    assert {:ok, moves} = result[node()]

    assert moves
           |> Enum.filter(fn {id, _} -> Supavisor.id(id, :tenant) in @tenants end)
           |> Enum.sort() ==
             Enum.sort(for tenant <- moved, do: {id(tenant, db_conf), @peer_node})

    for tenant <- moved do
      assert_eventually(20, 500, fn ->
        match?({:ok, %P.Result{}}, P.query(proxies[tenant], "SELECT 1", [], timeout: 1000)) and
          node(Supavisor.get_global_sup(id(tenant, db_conf))) == @peer_node
      end)
    end

    for tenant <- @tenants -- moved do
      assert %P.Result{rows: [[1]]} = P.query!(proxies[tenant], "SELECT 1", [])
      assert Supavisor.get_global_sup(id(tenant, db_conf)) == sups[tenant]
    end
  end

  defp index_of(node), do: [node(), @peer_node] |> Enum.sort() |> Enum.find_index(&(&1 == node))

  defp start_proxy(tenant, db_conf) do
    {:ok, proxy} =
      start_supervised(
        {P,
         hostname: db_conf[:hostname],
         port: Application.get_env(:supavisor, :proxy_port_transaction),
         database: db_conf[:database],
         password: db_conf[:password],
         username: db_conf[:username] <> "." <> tenant,
         backoff_min: 100,
         backoff_max: 500},
        id: {:proxy, tenant}
      )

    proxy
  end

  defp id(tenant, db_conf) do
    Supavisor.id(
      type: :single,
      tenant: tenant,
      user: db_conf[:username],
      mode: :transaction,
      db: db_conf[:database]
    )
  end

  defp gen_token do
    Supavisor.Jwt.Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))
  end
end
