defmodule Supavisor.Integration.StopPoolTest do
  use SupavisorWeb.ConnCase, async: false

  require Supavisor

  import Supavisor.Asserts, only: [assert_eventually: 1]

  alias Supavisor.JWT.SharedSecret.Token
  alias Supavisor.Support.Cluster

  @moduletag cluster: true

  # A committed (pre-seeded) tenant the peer node can read over its own DB
  # connection; see priv/repo/seeds_after_migration.exs.
  @tenant "cluster_pool_tenant_1"
  @secret %Supavisor.Secrets.PasswordSecrets{user: "postgres", password: "postgres"}

  setup %{conn: conn} do
    peer_name = :peer.random_name()
    {:ok, peer, peer_node} = Cluster.start_node(peer_name)
    true = Node.connect(peer_node)

    token = Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))

    conn =
      conn
      |> put_req_header("authorization", "Bearer " <> token)
      |> put_req_header("content-type", "application/json")

    %{conn: conn, peer: peer, peer_name: peer_name, peer_node: peer_node}
  end

  defp pool_id(db) do
    Supavisor.id(
      type: :single,
      tenant: @tenant,
      user: "postgres",
      mode: :transaction,
      db: db,
      search_path: nil
    )
  end

  test "stops a pool owned by another node with the pid from the pool list", %{
    conn: conn,
    peer: peer,
    peer_node: peer_node
  } do
    local_id = pool_id("supavisor_test")
    peer_id = pool_id("postgres")

    {:ok, _} = Supavisor.start(local_id, @secret)
    on_exit(fn -> Supavisor.stop(local_id) end)
    {:ok, _} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [peer_id, @secret])

    assert_eventually(fn -> is_pid(Supavisor.get_global_sup(peer_id)) end)
    peer_sup = Supavisor.get_global_sup(peer_id)
    local_sup = Supavisor.get_global_sup(local_id)
    assert is_pid(local_sup)
    assert node(peer_sup) == peer_node

    %{"pools" => pools} = conn |> get(~p"/api/tenants/#{@tenant}/pools") |> json_response(200)
    %{"pid" => pid} = Enum.find(pools, &(&1["node"] == to_string(peer_node)))

    assert conn
           |> delete(~p"/api/tenants/#{@tenant}/pools", Jason.encode!(%{pid: pid}))
           |> response(204)

    # `Process.alive?/1` only accepts local pids, so ask the peer.
    refute :erpc.call(peer_node, Process, :alive?, [peer_sup])
    # The same process: the local pool was neither stopped nor restarted.
    assert Supavisor.get_global_sup(local_id) == local_sup
  end

  test "stops a pool through another node's API with the pid from the pool list", %{
    conn: conn,
    peer: peer
  } do
    local_id = pool_id("supavisor_test")
    peer_id = pool_id("postgres")

    {:ok, _} = Supavisor.start(local_id, @secret)
    on_exit(fn -> Supavisor.stop(local_id) end)
    {:ok, _} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [peer_id, @secret])

    assert_eventually(fn -> is_pid(Supavisor.get_global_sup(peer_id)) end)
    peer_sup = Supavisor.get_global_sup(peer_id)
    local_sup = Supavisor.get_global_sup(local_id)
    assert is_pid(local_sup)

    %{"pools" => pools} = conn |> get(~p"/api/tenants/#{@tenant}/pools") |> json_response(200)
    %{"pid" => pid} = Enum.find(pools, &(&1["node"] == to_string(node())))

    # The peer's endpoint doesn't serve HTTP in tests, so dispatch the request on the peer.
    resp =
      :peer.call(peer, Phoenix.ConnTest, :dispatch, [
        conn,
        SupavisorWeb.Endpoint,
        :delete,
        ~p"/api/tenants/#{@tenant}/pools",
        Jason.encode!(%{pid: pid})
      ])

    assert response(resp, 204)
    refute Process.alive?(local_sup)
    # The same process: the peer's pool was neither stopped nor restarted.
    assert Supavisor.get_global_sup(peer_id) == peer_sup
  end

  test "stop_pool/3 reports a pid's node as unreachable once it is gone", %{
    peer: peer,
    peer_name: peer_name
  } do
    pid = :peer.call(peer, Process, :whereis, [:init])

    stop_supervised!({:peer, peer_name})

    assert {:error, :node_unreachable} = Supavisor.Ops.stop_pool(@tenant, pid)
  end
end
