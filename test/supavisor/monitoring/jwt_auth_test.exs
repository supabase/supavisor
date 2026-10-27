defmodule Supavisor.PromEx.Plugins.JWTAuthTest do
  use ExUnit.Case, async: true

  alias Supavisor.PromEx.Plugins.JWTAuth

  describe "event_metrics/1" do
    setup do
      metrics =
        JWTAuth.event_metrics([])
        |> Enum.flat_map(fn %PromEx.MetricTypes.Event{metrics: metrics} -> metrics end)

      %{metrics: Map.new(metrics, &{&1.event_name, &1})}
    end

    test "exports an ok counter tagged by method and pipeline", %{metrics: metrics} do
      assert %Telemetry.Metrics.Counter{} = metric = metrics[[:supavisor, :jwt_auth, :ok]]
      assert metric.name == [:supavisor, :jwt_auth, :ok]
      assert metric.tags == [:method, :pipeline]
      assert metric.description
    end

    test "exports a rejected counter tagged by method, pipeline and reason", %{metrics: metrics} do
      assert %Telemetry.Metrics.Counter{} = metric = metrics[[:supavisor, :jwt_auth, :rejected]]
      assert metric.name == [:supavisor, :jwt_auth, :rejected]
      assert metric.tags == [:method, :pipeline, :reason]
      assert metric.description
    end

    test "exports counters for the JokenJwks fetch events", %{metrics: metrics} do
      for {event, name} <- [
            {[:joken_jwks, :default_strategy, :signers], [:supavisor, :jwks, :fetch, :ok]},
            {[:joken_jwks, :default_strategy, :refetch], [:supavisor, :jwks, :refetch]},
            {[:joken_jwks, :http_fetcher, :exception], [:supavisor, :jwks, :fetch, :exception]}
          ] do
        assert %Telemetry.Metrics.Counter{} = metric = metrics[event]
        assert metric.name == name
        assert metric.tags == []
        assert metric.description
      end
    end
  end
end
