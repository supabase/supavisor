defmodule Supavisor.Integration.SecretInvalidationClusterTest do
  use Supavisor.DataCase, async: false

  require Supavisor
  import Supavisor.Asserts

  alias Supavisor.ClientAuthentication
  alias Supavisor.Support.Cluster
  alias Supavisor.Support.ClientAuthenticationHelpers

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
end
