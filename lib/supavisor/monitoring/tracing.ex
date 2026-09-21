defmodule Supavisor.Monitoring.Tracing do
  @moduledoc false

  @available Mix.target() == :otel and Code.ensure_loaded?(OpenTelemetry.Tracer)

  def available?, do: @available

  if @available do
    require OpenTelemetry.Tracer
    require OpenTelemetry.Span

    def start_connection(mode) do
      if enabled?() do
        OpenTelemetry.Tracer.start_span("supavisor.connect",
          attributes: %{"supavisor.mode" => Atom.to_string(mode)}
        )
      end
    end

    def start_query(%{mode: mode, tenant: tenant, db_name: db_name}) do
      if enabled?() do
        attributes = %{"db.system.name" => "postgresql", "supavisor.mode" => Atom.to_string(mode)}

        attributes =
          if is_binary(tenant),
            do: Map.put(attributes, "supavisor.tenant", tenant),
            else: attributes

        attributes =
          if is_binary(db_name),
            do: Map.put(attributes, "db.namespace", db_name),
            else: attributes

        OpenTelemetry.Tracer.start_span("supavisor.query", attributes: attributes)
      end
    end

    def connection_ready(nil, _tenant), do: :ok

    def connection_ready(span, tenant) do
      if is_binary(tenant) do
        OpenTelemetry.Span.set_attribute(span, "supavisor.tenant", tenant)
      end

      OpenTelemetry.Span.end_span(span)
      :ok
    end

    def checkout(nil, _outcome, _duration_us), do: :ok

    def checkout(span, outcome, duration_us) do
      OpenTelemetry.Span.add_event(span, "pool.checkout", %{
        "outcome" => Atom.to_string(outcome),
        "duration_us" => duration_us
      })

      :ok
    end

    def finish(nil, _outcome), do: :ok

    def finish(span, outcome) do
      if outcome == :error do
        OpenTelemetry.Span.set_status(span, :error)
      end

      OpenTelemetry.Span.end_span(span)
      :ok
    end

    defp enabled?, do: Application.get_env(:supavisor, :otel_enabled, false)
  else
    def start_connection(_mode), do: nil
    def start_query(_data), do: nil
    def connection_ready(nil, _tenant), do: :ok
    def connection_ready(_span, _tenant), do: :ok
    def checkout(nil, _outcome, _duration_us), do: :ok
    def checkout(_span, _outcome, _duration_us), do: :ok
    def finish(nil, _outcome), do: :ok
    def finish(_span, _outcome), do: :ok
  end
end
