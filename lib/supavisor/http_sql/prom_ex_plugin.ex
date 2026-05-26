defmodule Supavisor.HttpSql.PromExPlugin do
  @moduledoc """
  Registers Prometheus metrics for the HTTP /sql endpoint's telemetry events,
  mirroring the bucket conventions used by `Supavisor.PromEx.Plugins.Tenant`.

  Metrics emitted under `/metrics`:

    * `supavisor_http_sql_request_duration` (distribution, ms)
    * `supavisor_http_sql_requests_count` (counter)
    * `supavisor_http_sql_request_response_rows` (distribution)
    * `supavisor_http_sql_pool_checkout_duration` (distribution, ms)
    * `supavisor_http_sql_max_clients_rejected_count` (counter)
  """

  use PromEx.Plugin

  alias Supavisor.PromEx.Plugins.Tenant.Buckets

  @tags [:tenant, :user, :status_code, :mode, :batch_size]

  @impl true
  def event_metrics(_opts) do
    Event.build(
      :supavisor_http_sql_event_metrics,
      [
        # Request lifecycle ---------------------------------------------------
        distribution(
          [:supavisor, :http_sql, :request, :duration],
          event_name: [:supavisor, :http_sql, :request, :stop],
          measurement: :duration,
          description: "Latency of HTTP /sql requests, including pool checkout and query exec.",
          tags: @tags,
          unit: {:native, :millisecond},
          reporter_options: [peep_bucket_calculator: Buckets]
        ),
        counter(
          [:supavisor, :http_sql, :requests, :count],
          event_name: [:supavisor, :http_sql, :request, :stop],
          description: "Total HTTP /sql requests completed.",
          tags: @tags
        ),
        distribution(
          [:supavisor, :http_sql, :request, :response_rows],
          event_name: [:supavisor, :http_sql, :request, :stop],
          measurement: :response_rows,
          description: "Rows returned per HTTP /sql request.",
          tags: [:tenant, :user],
          reporter_options: [peep_bucket_calculator: Buckets]
        ),

        # Pool lifecycle ------------------------------------------------------
        distribution(
          [:supavisor, :http_sql, :pool, :checkout, :duration],
          event_name: [:supavisor, :http_sql, :pool, :checkout],
          measurement: :duration,
          description:
            "Latency of pool checkout: start_dist + Manager.subscribe + poolboy.checkout + DbHandler.checkout.",
          tags: [:tenant, :user, :hit?],
          unit: {:microsecond, :millisecond},
          reporter_options: [peep_bucket_calculator: Buckets]
        ),

        # Saturation ---------------------------------------------------------
        counter(
          [:supavisor, :http_sql, :max_clients_rejected, :count],
          event_name: [:supavisor, :http_sql, :max_clients_rejected],
          description:
            "HTTP /sql requests rejected by the tenant's Manager max_clients cap.",
          tags: [:tenant, :user, :limit_kind]
        )
      ]
    )
  end
end
