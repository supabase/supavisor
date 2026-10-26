defmodule Supavisor.PromEx.Plugins.JWTAuthTest do
  use ExUnit.Case, async: true

  alias Supavisor.PromEx.Plugins.JWTAuth

  describe "event_metrics/1" do
    setup do
      [%PromEx.MetricTypes.Event{metrics: metrics}] = JWTAuth.event_metrics([])
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
  end
end
