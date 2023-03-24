defmodule Supavisor.PromEx.Plugins.Tenant do
  @moduledoc "This module defines the PromEx plugin for Supavisor tenants."

  use PromEx.Plugin
  require Logger

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate, 5_000)

    [
      concurrent_connections(poll_rate)
    ]
  end

  @impl true
  def event_metrics(_opts) do
    [
      pool_metrics()
    ]
  end

  def pool_metrics() do
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

  defp concurrent_connections(poll_rate) do
    Polling.build(
      :supavisor_concurrent_connections,
      poll_rate,
      {__MODULE__, :execute_tenant_metrics, []},
      [
        last_value(
          [:supavisor, :connections, :connected],
          event_name: [:supavisor, :connections],
          description: "The total count of connected clients for a tenant.",
          measurement: :connected,
          tags: [:tenant]
        )
      ]
    )
  end

  def execute_tenant_metrics() do
    Registry.select(Supavisor.Registry.ManagerTables, [
      {{:"$1", :"$2", :"$3"}, [], [{{:"$1", :"$2", :"$3"}}]}
    ])
    |> Enum.each(&emit_telemetry_for_tenant/1)
  end

  @spec emit_telemetry_for_tenant({String.t(), pid(), reference()}) :: :ok
  defp emit_telemetry_for_tenant({tenant, _, tid}) do
    :telemetry.execute(
      [:supavisor, :connections],
      %{connected: :ets.info(tid, :size)},
      %{tenant: tenant}
    )
  end
end
