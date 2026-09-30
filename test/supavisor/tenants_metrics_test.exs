defmodule Supavisor.TenantsMetricsTest do
  use Supavisor.DataCase, async: false

  require Supavisor

  alias Supavisor.Monitoring.PromEx
  alias Supavisor.PromEx.Plugins.Tenant

  describe "handle_info(:check_metrics, state)" do
    test "one pool disappearing wipes the cached metrics of every other still-active pool for the same tenant" do
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

      # Second check cycle, second half: handle_info then deletes the cache
      # entry for every pool that dropped out - keyed only on `tenant`, not on
      # the full pool identity - which wipes the transaction pool's data it
      # had just written above.
      {:noreply, _state} = Supavisor.TenantsMetrics.handle_info(:check_metrics, state)

      assert PromEx.get_tenant_metrics(tenant) |> IO.iodata_to_binary() == ""
      assert {:ok, nil} = Cachex.get(Supavisor.Cache, {:metrics, tenant})
    end
  end
end
