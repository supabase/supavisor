defmodule Supavisor.Integration.ManagerCacheInvalidationClusterTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  alias Supavisor.ClientAuthentication
  alias Supavisor.Manager
  alias Supavisor.Support.Cluster
  alias Supavisor.Support.Cluster.PortConfig
  alias Supavisor.Support.ClientAuthenticationHelpers
  alias Supavisor.Support.ManagerTestHelpers

  defp id(tenant, user, mode \\ :transaction) do
    Supavisor.id(type: :single, tenant: tenant, user: user, mode: mode, db: "postgres")
  end

  defp seed_caches(tenant, user, peer) do
    secrets = ClientAuthenticationHelpers.build_validation_secrets(user)

    ClientAuthentication.put_validation_secrets(tenant, user, secrets)
    :peer.call(peer, ClientAuthentication, :put_validation_secrets, [tenant, user, secrets])
  end

  defp start_test_node1,
    do:
      Cluster.start_node_unclustered(
        :mgr_test_node_1,
        %PortConfig{
          proxy_port_transaction: 7664,
          proxy_port_session: 7665,
          proxy_port: 7666,
          session_proxy_ports: [15_100, 15_101, 15_102, 15_103],
          transaction_proxy_ports: [15_104, 15_105, 15_106, 15_107]
        }
      )

  defp start_test_node2,
    do:
      Cluster.start_node_unclustered(
        :mgr_test_node_2,
        %PortConfig{
          proxy_port_transaction: 7667,
          proxy_port_session: 7668,
          proxy_port: 7669,
          session_proxy_ports: [16_100, 16_101, 16_102, 16_103],
          transaction_proxy_ports: [16_104, 16_105, 16_106, 16_107]
        }
      )

  defp start_sibling_manager(node, sibling_id) do
    Node.spawn(node, ManagerTestHelpers, :sibling_loop, [sibling_id, self()])

    receive do
      :registered ->
        nil
    after
      500 -> flunk("failed to register sibling manager at #{node}")
    end
  end

  # `Manager.terminate/2` is called directly below, bypassing `start_link/1` — but in
  # production the terminating manager is still registered in the Registry while its own
  # `terminate/2` runs (deregistration only happens once the process actually exits, which
  # is after `terminate/2` returns). Register the id under test on the primary node to
  # mirror that, so `pools_count_global/2,3` sees the same count it would in production.
  defp register_self(id) do
    {:ok, _} = Registry.register(Supavisor.Registry.Tenants, {:manager, id}, nil)
  end

  @tag cluster: true
  test "does not invalidate the cache when a sibling pool for the same tenant+user runs on another node" do
    {:ok, peer, node} = start_test_node1()
    Node.connect(node)
    assert node in Node.list()

    tenant = "mgr_cluster_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user, :transaction)

    register_self(self_id)
    start_sibling_manager(node, id(tenant, user, :session))
    seed_caches(tenant, user, peer)

    Manager.terminate(:shutdown, %{id: self_id})

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)

    assert {:ok, _} =
             :peer.call(peer, ClientAuthentication, :get_validation_secrets, [tenant, user])
  end

  @tag cluster: true
  test "invalidates the cache even when a pool for a different user (same tenant) runs on another node" do
    {:ok, peer, node} = start_test_node2()
    Node.connect(node)
    assert node in Node.list()

    tenant = "mgr_cluster_test_#{System.unique_integer([:positive])}"
    user = "user1"
    other_user = "user2"
    self_id = id(tenant, user)

    register_self(self_id)
    start_sibling_manager(node, id(tenant, other_user))
    seed_caches(tenant, user, peer)

    Manager.terminate(:shutdown, %{id: self_id})

    assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)

    assert {:error, :not_found} =
             :peer.call(peer, ClientAuthentication, :get_validation_secrets, [tenant, user])
  end
end
