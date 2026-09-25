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

  defp register_sibling(id) do
    parent = self()

    spawn_link(fn ->
      {:ok, _} = Registry.register(Supavisor.Registry.Tenants, {:manager, id}, nil)
      send(parent, :registered)

      receive do
        :never_die -> :ok
      end
    end)

    assert_receive :registered
  end

  defp simulate_shutdown(self_id) do
    parent = self()

    spawn(fn ->
      Logger.metadata(
        project: Supavisor.id(self_id, :tenant),
        user: Supavisor.id(self_id, :user),
        type: Supavisor.id(self_id, :type),
        db_name: Supavisor.id(self_id, :db)
      )

      register(self_id)
      {:ok, invalidation_task_pid} = Manager.terminate(:shutdown, %{id: self_id})
      send(parent, {:task_pid, invalidation_task_pid})
    end)

    task_pid =
      receive do
        {:task_pid, task_pid} ->
          task_pid
      after
        500 ->
          flunk("timeout waiting for the task invalidation pid")
      end

    ref = Process.monitor(task_pid)

    receive do
      {:DOWN, ^ref, :process, ^task_pid, _reason} ->
        :ok
    after
      500 ->
        flunk("timeout waiting for the cache invalidation task to finish")
    end
  end

  test "invalidates the cache when no other pool exists for tenant+user" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    seed_cache(tenant, user)

    assert capture_log(fn ->
             simulate_shutdown(self_id)
           end) =~
             ~r/project=#{tenant}.*user=#{user}.*Invalidating client authentication globally/

    assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different mode)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user, mode: :transaction)
    register_sibling(id(tenant, user, mode: :session))
    seed_cache(tenant, user)

    simulate_shutdown(self_id)

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different upstream_tls)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    register_sibling(id(tenant, user, tls: true))
    seed_cache(tenant, user)

    simulate_shutdown(self_id)

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different db)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    register_sibling(id(tenant, user, db: "other_db"))
    seed_cache(tenant, user)

    simulate_shutdown(self_id)

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "does not invalidate the cache when a sibling pool for the same tenant+user is running (different search_path)" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    self_id = id(tenant, user)
    register_sibling(id(tenant, user, search_path: "my_search_path"))
    seed_cache(tenant, user)

    simulate_shutdown(self_id)

    assert {:ok, _} = ClientAuthentication.get_validation_secrets(tenant, user)
  end

  test "invalidates the cache even when a pool for a different user (same tenant) is running" do
    tenant = "mgr_test_#{System.unique_integer([:positive])}"
    user = "user1"
    other_user = "user2"
    self_id = id(tenant, user)

    register_sibling(id(tenant, other_user))
    seed_cache(tenant, user)

    assert capture_log(fn ->
             simulate_shutdown(self_id)
           end) =~
             ~r/project=#{tenant}.*user=#{user}.*Invalidating client authentication globally/

    assert {:error, :not_found} = ClientAuthentication.get_validation_secrets(tenant, user)
  end
end
