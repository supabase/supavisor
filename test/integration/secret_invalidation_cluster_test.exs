defmodule Supavisor.Integration.SecretInvalidationClusterTest do
  use Supavisor.DataCase, async: false

  require Supavisor
  import ExUnit.CaptureLog
  import Supavisor.Asserts

  alias Supavisor.ClientAuthentication
  alias Supavisor.Support.ClientAuthenticationHelpers
  alias Supavisor.Support.Cluster

  @moduletag cluster: true

  @tenant "secret_invalidation_tenant"
  @user "postgres"

  defp id(mode \\ :transaction) do
    Supavisor.id(type: :single, tenant: @tenant, user: @user, mode: mode, db: "postgres")
  end

  defp secret do
    %Supavisor.Secrets.PasswordSecrets{user: @user, password: "postgres"}
  end

  defp seed_caches(tenant, user, peer) do
    secrets = ClientAuthenticationHelpers.build_validation_secrets(user)

    ClientAuthentication.put_validation_secrets(tenant, user, secrets)
    :peer.call(peer, ClientAuthentication, :put_validation_secrets, [tenant, user, secrets])
  end

  test "invalidates the cache on every node when the last pool for tenant+user shuts down" do
    {:ok, peer, node} = Cluster.start_node()
    true = Node.connect(node)

    self_id = id()
    {:ok, _pid} = Supavisor.start(self_id, secret())
    seed_caches(@tenant, @user, peer)

    :ok = Supavisor.stop(self_id)
    assert_eventually(fn -> Supavisor.get_global_sup(self_id) == nil end)

    assert_eventually(fn ->
      ClientAuthentication.get_validation_secrets(@tenant, @user) == {:error, :not_found}
    end)

    assert_eventually(fn ->
      :peer.call(peer, ClientAuthentication, :get_validation_secrets, [@tenant, @user]) ==
        {:error, :not_found}
    end)
  end

  test "does not invalidate the cache while a sibling pool for the same tenant+user is running on another node" do
    {:ok, peer, node} = Cluster.start_node()
    true = Node.connect(node)

    self_id = id(:transaction)
    sibling_id = id(:session)
    {:ok, _sibling_pid} = :peer.call(peer, Supavisor, :start, [sibling_id, secret()])
    {:ok, _pid} = Supavisor.start(self_id, secret())
    seed_caches(@tenant, @user, peer)

    :ok = Supavisor.stop(self_id)
    assert_eventually(fn -> Supavisor.get_global_sup(self_id) == nil end)

    refute_eventually(fn ->
      ClientAuthentication.get_validation_secrets(@tenant, @user) == {:error, :not_found}
    end)

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(@tenant, @user)

    assert {:ok, _} =
             :peer.call(peer, ClientAuthentication, :get_validation_secrets, [@tenant, @user])
  end

  test "does not invalidate the cache while the last pool for tenant+user is still draining" do
    {:ok, peer, node} = Cluster.start_node()
    true = Node.connect(node)

    self_id = id()
    {:ok, sup} = Supavisor.start(self_id, secret())
    seed_caches(@tenant, @user, peer)

    # A connected "client" keeps Manager.graceful_shutdown/3 draining until it goes away.
    subscriber = spawn(fn -> Process.sleep(:infinity) end)
    {:ok, _} = Supavisor.subscribe(self_id, subscriber)
    {:ok, _task} = Supavisor.async_stop(sup)

    # Supavisor.Terminator has de-registered the pool from :tenants (routing)...
    assert_eventually(_repeats = 20, 50, fn -> Supavisor.get_global_sup(self_id) == nil end)
    # ...but it's still alive and still a :tenant_pools member while draining.
    assert Process.alive?(sup)
    assert sup in Supavisor.tenant_pools(@tenant, @user)

    # Give a (wrong) early invalidation time to land, still well inside the 2.5s drain.
    Process.sleep(500)
    assert {:ok, _} = ClientAuthentication.get_validation_secrets(@tenant, @user)

    assert {:ok, _} =
             :peer.call(peer, ClientAuthentication, :get_validation_secrets, [@tenant, @user])

    # Finish the drain: the pool really dies and only now is the cache invalidated everywhere.
    Process.exit(subscriber, :kill)

    assert_eventually(fn -> not Process.alive?(sup) end)

    assert_eventually(fn ->
      ClientAuthentication.get_validation_secrets(@tenant, @user) == {:error, :not_found}
    end)

    assert_eventually(fn ->
      :peer.call(peer, ClientAuthentication, :get_validation_secrets, [@tenant, @user]) ==
        {:error, :not_found}
    end)
  end

  test "invalidates the cache when the node hosting every pool for tenant+user goes down" do
    {:ok, peer, node} = Cluster.start_node()
    true = Node.connect(node)

    {:ok, _} = :peer.call(peer, Supavisor, :start, [id(:transaction), secret()])
    {:ok, _} = :peer.call(peer, Supavisor, :start, [id(:session), secret()])
    assert_eventually(fn -> length(Supavisor.tenant_pools(@tenant, @user)) == 2 end)

    secrets = ClientAuthenticationHelpers.build_validation_secrets(@user)
    ClientAuthentication.put_validation_secrets(@tenant, @user, secrets)

    # :peer's default shutdown halts the node, so both pools leave via the node-down purge,
    # which calls back before deleting either.
    log =
      capture_log([level: :debug], fn ->
        :peer.stop(peer)

        assert_eventually(fn ->
          ClientAuthentication.get_validation_secrets(@tenant, @user) == {:error, :not_found}
        end)
      end)

    assert log =~ "{:syn_remote_scope_node_down, :tenant_pools,"
  end
end
