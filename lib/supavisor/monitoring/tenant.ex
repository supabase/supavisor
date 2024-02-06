defmodule Supavisor.PromEx.Plugins.Tenant do
  @moduledoc "This module defines the PromEx plugin for Supavisor tenants."

  use PromEx.Plugin
  require Logger

  alias Supavisor, as: S

  @tags [:tenant, :user, :mode, :type, :db_name]

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate, 5_000)

    [
      concurrent_connections(poll_rate),
      concurrent_tenants(poll_rate)
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
          [:supavisor, :pool, :checkout, :duration, :local],
          event_name: [:supavisor, :pool, :checkout, :stop, :local],
          measurement: :duration,
          description: "Duration of the checkout local process in the tenant db pool.",
          tags: @tags,
          unit: {:microsecond, :millisecond},
          reporter_options: [
            buckets: [1, 5, 10, 100, 1_000, 5_000, 10_000]
          ]
        ),
        distribution(
          [:supavisor, :pool, :checkout, :duration, :remote],
          event_name: [:supavisor, :pool, :checkout, :stop, :remote],
          measurement: :duration,
          description: "Duration of the checkout remote process in the tenant db pool.",
          tags: @tags,
          unit: {:microsecond, :millisecond},
          reporter_options: [
            buckets: [1, 5, 10, 100, 1_000, 5_000, 10_000]
          ]
        ),
        distribution(
          [:supavisor, :client, :query, :duration],
          event_name: [:supavisor, :client, :query, :stop],
          measurement: :duration,
          description: "Duration of processing the query.",
          tags: @tags,
          unit: {:native, :millisecond},
          reporter_options: [
            buckets: [1, 5, 10, 100, 1_000, 5_000, 10_000]
          ]
        ),
        distribution(
          [:supavisor, :client, :connection, :duration],
          event_name: [:supavisor, :client, :connection, :stop],
          measurement: :duration,
          description: "Duration from the TCP connection to sending greetings to clients.",
          tags: @tags,
          unit: {:native, :millisecond},
          reporter_options: [
            buckets: [1, 5, 10, 100, 1_000, 5_000, 10_000]
          ]
        ),
        sum(
          [:supavisor, :client, :network, :recv],
          event_name: [:supavisor, :client, :network, :stat],
          measurement: :recv_oct,
          description: "The total number of bytes received by clients.",
          tags: @tags
        ),
        sum(
          [:supavisor, :client, :network, :send],
          event_name: [:supavisor, :client, :network, :stat],
          measurement: :send_oct,
          description: "The total number of bytes sent by clients.",
          tags: @tags
        ),
        counter(
          [:supavisor, :client, :queries, :count],
          event_name: [:supavisor, :client, :query, :stop],
          description: "The total number of queries received by clients.",
          tags: @tags
        ),
        counter(
          [:supavisor, :client, :joins, :ok],
          event_name: [:supavisor, :client, :joins, :ok],
          description: "The total number of successful joins.",
          tags: @tags
        ),
        counter(
          [:supavisor, :client, :joins, :fail],
          event_name: [:supavisor, :client, :joins, :fail],
          description: "The total number of failed joins.",
          tags: @tags
        ),
        counter(
          [:supavisor, :client_handler, :started, :count],
          event_name: [:supavisor, :client_handler, :started, :all],
          description: "The total number of created client_handler.",
          tags: @tags
        ),
        counter(
          [:supavisor, :client_handler, :stopped, :count],
          event_name: [:supavisor, :client_handler, :stopped, :all],
          description: "The total number of stopped client_handler.",
          tags: @tags
        ),
        counter(
          [:supavisor, :db_handler, :started, :count],
          event_name: [:supavisor, :db_handler, :started, :all],
          description: "The total number of created db_handler.",
          tags: @tags
        ),
        counter(
          [:supavisor, :db_handler, :stopped, :count],
          event_name: [:supavisor, :db_handler, :stopped, :all],
          description: "The total number of stopped db_handler.",
          tags: @tags
        ),
        counter(
          [:supavisor, :db_handler, :db_connection, :count],
          event_name: [:supavisor, :db_handler, :db_connection, :all],
          description: "The total number of database connections by db_handler.",
          tags: @tags
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
          tags: @tags
        ),
        sum(
          [:supavisor, :db, :network, :send],
          event_name: [:supavisor, :db, :network, :stat],
          measurement: :send_oct,
          description: "The total number of bytes sent by db process",
          tags: @tags
        )
      ]
    )
  end

  def concurrent_connections(poll_rate) do
    Polling.build(
      :supavisor_concurrent_connections,
      poll_rate,
      {__MODULE__, :execute_tenant_metrics, []},
      [
        last_value(
          [:supavisor, :connections, :active],
          event_name: [:supavisor, :connections],
          description: "The total count of active clients for a tenant.",
          measurement: :active,
          tags: @tags
        )
      ]
    )
  end

  def execute_tenant_metrics() do
    Registry.select(Supavisor.Registry.TenantClients, [{{:"$1", :_, :_}, [], [:"$1"]}])
    |> Enum.frequencies()
    |> Enum.each(&emit_telemetry_for_tenant/1)
  end

  @spec emit_telemetry_for_tenant({S.id(), non_neg_integer()}) :: :ok
  def emit_telemetry_for_tenant({{{type, tenant}, user, mode, db_name}, count}) do
    :telemetry.execute(
      [:supavisor, :connections],
      %{active: count},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  def concurrent_tenants(poll_rate) do
    Polling.build(
      :supavisor_concurrent_tenants,
      poll_rate,
      {__MODULE__, :execute_conn_tenants_metrics, []},
      [
        last_value(
          [:supavisor, :tenants, :active],
          event_name: [:supavisor, :tenants],
          description: "The total count of active tenants.",
          measurement: :active
        )
      ]
    )
  end

  def execute_conn_tenants_metrics() do
    num =
      Registry.select(Supavisor.Registry.TenantSups, [{{:"$1", :_, :_}, [], [:"$1"]}])
      |> Enum.uniq()
      |> Enum.count()

    :telemetry.execute(
      [:supavisor, :tenants],
      %{active: num}
    )
  end
end
