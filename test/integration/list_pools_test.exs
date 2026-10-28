defmodule Supavisor.Integration.ListPoolsTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  import Supavisor.Asserts, only: [assert_eventually: 1]

  alias Supavisor.Ops
  alias Supavisor.Support.Cluster

  @moduletag cluster: true

  # A committed (pre-seeded) tenant the peer node can read over its own DB
  # connection; see priv/repo/seeds_after_migration.exs.
  @tenant "cluster_pool_tenant_1"
  @secret %Supavisor.Secrets.PasswordSecrets{user: "postgres", password: "postgres"}

  setup do
    {:ok, peer, peer_node} = Cluster.start_node()
    true = Node.connect(peer_node)
    %{peer: peer, peer_node: peer_node}
  end

  defp pool_id(db, search_path \\ nil) do
    Supavisor.id(
      type: :single,
      tenant: @tenant,
      user: "postgres",
      mode: :transaction,
      db: db,
      search_path: search_path
    )
  end

  defp pools do
    {:ok, %{pools: pools}} = Ops.list_pools(@tenant)
    pools
  end

  # `assert_eventually/1` only says "Expected function to return truthy value", so
  # show what was actually listed.
  defp assert_pools_eventually(function) do
    assert_eventually(function)
  rescue
    e in ExUnit.AssertionError ->
      reraise %{e | message: e.message <> "\nlist_pools: " <> inspect(Ops.list_pools(@tenant))},
              __STACKTRACE__
  end

  # Starts a distinct pool on this node and on the peer.
  defp start_pool_on_both(peer) do
    local_id =
      pool_id(
        "supavisor_test",
        "list_pools_#{Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)}"
      )

    peer_id = pool_id("postgres")

    {:ok, _} = Supavisor.start(local_id, @secret)
    on_exit(fn -> Supavisor.stop(local_id) end)
    {:ok, _} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [peer_id, @secret])

    {local_id, peer_id}
  end

  test "list_pools/1 aggregates pools from every node", %{peer: peer, peer_node: peer_node} do
    {local_id, peer_id} = start_pool_on_both(peer)

    assert_pools_eventually(fn ->
      {:ok, %{pools: pools, errors: errors}} = Ops.list_pools(@tenant)

      errors == %{} and
        Enum.any?(pools, &(&1.id == local_id and &1.node == node())) and
        Enum.any?(pools, &(&1.id == peer_id and &1.node == peer_node))
    end)
  end

  test "list_pools/1 returns the peer pool's supervisor pid", %{peer: peer, peer_node: peer_node} do
    {_local_id, peer_id} = start_pool_on_both(peer)

    assert_eventually(fn -> is_pid(Supavisor.get_global_sup(peer_id)) end)
    peer_sup = Supavisor.get_global_sup(peer_id)
    assert node(peer_sup) == peer_node

    assert %{pid: ^peer_sup, pid_label: pid_label, status: :active} =
             Enum.find(pools(), &(&1.id == peer_id))

    # As the peer prints it, not as a remote pid on this node.
    assert pid_label == :peer.call(peer, Kernel, :inspect, [peer_sup])
    assert "#PID<0." <> _ = pid_label
  end

  test "list_pools_local/1 returns only this node's pools", %{peer: peer} do
    {local_id, peer_id} = start_pool_on_both(peer)

    # Wait until the peer pool is visible cluster-wide, so we know it started.
    assert_pools_eventually(fn -> Enum.any?(pools(), &(&1.id == peer_id)) end)

    assert [local] = Ops.list_pools_local(@tenant)
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
    id = pool_id(db_conf[:database])
    {:ok, peer_sup} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [id, @secret])

    # `Supavisor.start/2` returns the pool already registered for the id, if any.
    assert node(peer_sup) == peer_node

    assert_pools_eventually(fn ->
      Enum.any?(pools(), &(&1.id == id and &1.node == peer_node))
    end)

    {:ok, client} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
        database: db_conf[:database],
        password: db_conf[:password],
        username: "#{db_conf[:username]}.#{@tenant}"
      )

    assert %Postgrex.Result{rows: [[1]]} = Postgrex.query!(client, "SELECT 1", [])

    assert_pools_eventually(fn ->
      match?(%{clients: 1}, Enum.find(pools(), &(&1.id == id)))
    end)

    # A direct (owner-side) subscriber on the peer adds to the same count.
    local_sub = :peer.call(peer, :erlang, :spawn, [:timer, :sleep, [:infinity]])
    {:ok, _} = :peer.call(peer, Supavisor, :subscribe, [id, local_sub])

    assert_pools_eventually(fn ->
      match?(%{clients: 2}, Enum.find(pools(), &(&1.id == id)))
    end)
  end
end
