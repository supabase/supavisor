defmodule Supavisor.PromEx.Plugins.Tenant do
  @moduledoc "This module defines the PromEx plugin for Supavisor tenants."

  use PromEx.Plugin
  require Logger

  @impl true
  def event_metrics(_opts) do
    [
      replication_metrics()
    ]
  end

  def replication_metrics() do
    Event.build(
      :supavisor_tenant_checkout_event_metrics,
      [
        distribution(
          [:supavisor, :pool, :checkout, :duration],
          event_name: [:supavisor, :pool, :checkout, :stop],
          measurement: :duration,
          description: "Duration of the checkout process in the tenant db pool.",
          tags: [:tenant],
          unit: {:microsecond, :millisecond},
          reporter_options: [
            buckets: [125, 250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000]
          ]
        )
      ]
    )
  end
end
