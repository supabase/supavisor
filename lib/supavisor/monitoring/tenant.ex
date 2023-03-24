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
      client_metrics(),
      db_metrics()
    ]
  end

  def client_metrics() do
    Event.build(
      :supavisor_tenant_client_event_metrics,
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
        ),
        sum(
          [:supavisor, :client, :network, :recv],
          event_name: [:supavisor, :client, :network, :stat],
          measurement: :recv_oct,
          description: "The total number of bytes received by clients.",
          tags: [:tenant]
        ),
        sum(
          [:supavisor, :client, :network, :send],
          event_name: [:supavisor, :client, :network, :stat],
          measurement: :send_oct,
          description: "The total number of bytes sent by clients.",
          tags: [:tenant]
        )
      ]
    )
  end

  def db_metrics() do
    Event.build(
      :supavisor_tenant_db_event_metrics,
      [
        sum(
          [:supavisor, :db, :network, :recv],
          event_name: [:supavisor, :db, :network, :stat],
          measurement: :recv_oct,
          description: "The total number of bytes received by db process",
          tags: [:tenant]
        ),
        sum(
          [:supavisor, :db, :network, :send],
          event_name: [:supavisor, :db, :network, :stat],
          measurement: :send_oct,
          description: "The total number of bytes sent by db process",
          tags: [:tenant]
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

  @spec emit_telemetry_for_tenant({String.t(), pid(), :ets.tid()}) :: :ok
  defp emit_telemetry_for_tenant({tenant, _, tid}) do
    :telemetry.execute(
      [:supavisor, :connections],
      %{connected: :ets.info(tid, :size)},
      %{tenant: tenant}
    )
  end
end
