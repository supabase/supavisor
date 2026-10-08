defmodule Supavisor.TenantsMetricsTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  alias Supavisor.Monitoring.PromEx
  alias Supavisor.PromEx.Plugins.Tenant

  describe "handle_info(:check_metrics, state)" do
    test "one pool disappearing does not wipe the cached metrics of other still-active pools for the same tenant" do
      tenant = "tenants_metrics_bug_#{System.unique_integer([:positive])}"

      transaction_id =
        Supavisor.id(
          type: :single,
          tenant: tenant,
          user: "app_user",
          mode: :transaction,
          db: "db_name"
        )

      session_id =
        Supavisor.id(
          type: :single,
          tenant: tenant,
          user: "report_user",
          mode: :session,
          db: "db_name"
        )

      # Two distinct pools for the same tenant: one under steady transaction-mode
      # load, one occasional session-mode client
      Registry.register(Supavisor.Registry.TenantClients, transaction_id, [])
      Registry.register(Supavisor.Registry.TenantClients, session_id, [])

      Tenant.emit_telemetry_for_tenant(transaction_id, 5, "app")
      Tenant.emit_telemetry_for_tenant(session_id, 1, "app")

      state = %{check_ref: make_ref(), pools: MapSet.new()}

      # First check cycle: both pools are seen, the tenant's cache holds both.
      {:noreply, state} = Supavisor.TenantsMetrics.handle_info(:check_metrics, state)

      metrics_with_both_pools = PromEx.get_tenant_metrics(tenant) |> IO.iodata_to_binary()
      assert metrics_with_both_pools =~ ~s(mode="transaction")
      assert metrics_with_both_pools =~ ~s(mode="session")

      # The session-mode client disconnects.
      Registry.unregister(Supavisor.Registry.TenantClients, session_id)

      # Second check cycle, first half: do_cache_tenants_metrics/0 repopulates
      # the cache from the still-live transaction pool's data.
      repopulated_pools = PromEx.do_cache_tenants_metrics()
      assert transaction_id in repopulated_pools
      refute session_id in repopulated_pools

      metrics_after_repopulation = PromEx.get_tenant_metrics(tenant) |> IO.iodata_to_binary()
      assert metrics_after_repopulation =~ ~s(mode="transaction")

      # Second check cycle, second half: handle_info only deletes the cache
      # entry for a tenant once none of its pools are active anymore. The
      # transaction pool is still live, so its freshly-cached data survives.
      {:noreply, state} = Supavisor.TenantsMetrics.handle_info(:check_metrics, state)

      metrics_after_session_drop = PromEx.get_tenant_metrics(tenant) |> IO.iodata_to_binary()
      assert metrics_after_session_drop =~ ~s(mode="transaction")
      assert {:ok, metrics} = Cachex.get(Supavisor.Cache, {:metrics, tenant})
      assert is_map(metrics)

      # Now the last remaining pool for the tenant also disappears: this time
      # the cache entry should actually be cleared.
      Registry.unregister(Supavisor.Registry.TenantClients, transaction_id)

      {:noreply, _state} = Supavisor.TenantsMetrics.handle_info(:check_metrics, state)

      assert PromEx.get_tenant_metrics(tenant) |> IO.iodata_to_binary() == ""
      assert {:ok, nil} = Cachex.get(Supavisor.Cache, {:metrics, tenant})
    end
  end
end
