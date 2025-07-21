defmodule Supavisor.MetricsCleanerTest do
  use ExUnit.Case, async: false

  alias Supavisor.PromEx.Plugins.Tenant, as: Metrics

  @subject Supavisor.MetricsCleaner

  doctest @subject

  setup ctx do
    :telemetry.attach(ctx, [:supavisor, :metrics_cleaner, :stop], &__MODULE__.handler/4, %{
      parent: self()
    })

    :ok
  end

  def handler(_, measurements, _, %{parent: pid}) do
    send(pid, {:metrics, measurements})
  end

  test "metrics for unknown tenant are removed" do
    :ok =
      Metrics.emit_telemetry_for_tenant(
        {{{:single, "non-existent"}, "foo", :transaction, "bar", nil}, 2137}
      )

    metrics = Supavisor.Monitoring.PromEx.get_metrics()

    assert IO.iodata_to_binary(metrics) =~ ~r/non-existent/

    @subject.clean()

    assert_receive {:metrics, _}

    metrics = Supavisor.Monitoring.PromEx.get_metrics()

    refute IO.iodata_to_binary(metrics) =~ ~r/non-existent/
  end
end
