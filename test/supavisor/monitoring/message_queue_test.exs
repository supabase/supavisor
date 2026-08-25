defmodule Supavisor.PromEx.Plugins.MessageQueueTest do
  use Supavisor.E2ECase, async: false

  alias Supavisor.PromEx.Plugins.MessageQueue

  @moduletag telemetry: true

  describe "polling_metrics/1" do
    test "properly exports metrics" do
      for polling_metric <- MessageQueue.polling_metrics([]) do
        assert %PromEx.MetricTypes.Polling{metrics: [_ | _]} = polling_metric
        {m, f, a} = polling_metric.measurements_mfa
        assert function_exported?(m, f, length(a))

        for telemetry_metric <- polling_metric.metrics do
          assert Enum.any?(
                   [
                     Telemetry.Metrics.Distribution,
                     Telemetry.Metrics.Counter,
                     Telemetry.Metrics.LastValue,
                     Telemetry.Metrics.Sum
                   ],
                   fn struct -> is_struct(telemetry_metric, struct) end
                 )

          assert telemetry_metric.description
        end
      end
    end

    test "uses poll rate option" do
      for polling_metric <- MessageQueue.polling_metrics(poll_rate: 1000) do
        assert %{poll_rate: 1000} = polling_metric
      end
    end

    test "reports message queue length as a gauge tagged by process name" do
      metrics =
        MessageQueue.polling_metrics([])
        |> Enum.flat_map(& &1.metrics)

      name = [:supavisor, :prom_ex, :process, :message_queue_len]
      metric = Enum.find(metrics, &(&1.name == name))

      assert metric, "expected a message queue metric named #{inspect(name)}"
      assert is_struct(metric, Telemetry.Metrics.LastValue)
      assert metric.tags == [:name]
    end
  end

  describe "execute_metrics/0" do
    test "emits one event per running process tagged by name" do
      ref = attach_handler([:supavisor, :prom_ex, :process])

      assert :ok = MessageQueue.execute_metrics()

      for name <- [
            "rex",
            "syn_registry_tenants",
            "syn_pg_tenants",
            "syn_registry_availability_zone",
            "syn_pg_availability_zone",
            "Supavisor.ErlSysMon",
            "Supavisor.PoolTerminator",
            "Supavisor.Cache_courier"
          ] do
        assert_receive {^ref,
                        {[:supavisor, :prom_ex, :process], measurement, %{name: ^name}}}

        assert %{message_queue_len: len} = measurement
        assert is_integer(len) and len >= 0
      end
    end
  end

  def handle_event(event_name, measurement, meta, {pid, ref}) do
    send(pid, {ref, {event_name, measurement, meta}})
  end

  defp attach_handler(event) do
    ref = make_ref()

    :telemetry.attach(
      {ref, :test},
      event,
      &__MODULE__.handle_event/4,
      {self(), ref}
    )

    on_exit(fn ->
      :telemetry.detach({ref, :test})
    end)

    ref
  end
end
