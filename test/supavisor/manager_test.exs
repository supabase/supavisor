defmodule Supavisor.ManagerTest do
  use ExUnit.Case, async: false

  require Supavisor
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import Supavisor.Support.ClientAuthenticationHelpers

  alias Supavisor.ClientAuthentication
  alias Supavisor.Manager

  defp id(tenant, user, opts \\ []) do
    Supavisor.id(
      type: :single,
      tenant: tenant,
      user: user,
      mode: opts[:mode] || :transaction,
      db: opts[:db] || "postgres",
      upstream_tls: opts[:tls] || false,
      search_path: opts[:search_path] || nil
    )
  end

  # `Manager.terminate/2` is called directly below, bypassing `start_link/1` — but in
  # production the terminating manager is still registered in the Registry while its own
  # `terminate/2` runs (Registry deregistration only happens once the process actually
  # exits, which is after `terminate/2` returns). Register the id under test to mirror that,
  # so `pools_count_global/2,3` sees the same count it would in production.
  defp register(id) do
    {:ok, _} = Registry.register(Supavisor.Registry.Tenants, {:manager, id}, nil)
  end

  test "invalidates the cache when no other pool exists for tenant+user" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    register(self_id)
    seed_cache(tenant, user)

    Manager.terminate(:shutdown, %{id: self_id})

    assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different mode)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user, mode: :transaction)
    register(self_id)
    register(id(tenant, user, mode: :session))
    seed_cache(tenant, user)

    Manager.terminate(:shutdown, %{id: self_id})

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different upstream_tls)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    register(self_id)
    register(id(tenant, user, tls: true))
    seed_cache(tenant, user)

    Manager.terminate(:shutdown, %{id: self_id})

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different db)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    register(self_id)
    register(id(tenant, user, db: "other_db"))
    seed_cache(tenant, user)

    Manager.terminate(:shutdown, %{id: self_id})

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different search_path)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    register(self_id)
    register(id(tenant, user, search_path: "my_search_path"))
    seed_cache(tenant, user)

    Manager.terminate(:shutdown, %{id: self_id})

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "invalidates the cache even when a pool for a different user (same tenant) is running" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    other_user = "user2"
    self_id = id(tenant, user)

    register(self_id)

    Logger.metadata(
      project: tenant,
      user: user,
      type: Supavisor.id(self_id, :type),
      db_name: Supavisor.id(self_id, :db)
    )

    register(id(tenant, other_user))
    seed_cache(tenant, user)

    assert capture_log(fn ->
             Manager.terminate(:shutdown, %{id: self_id})
           end) =~
             ~r/project=#{tenant}.*user=#{user}.*Invalidating client authentication globally/

    assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)
  end
end
