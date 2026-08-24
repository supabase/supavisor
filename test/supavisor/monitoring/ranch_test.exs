defmodule Supavisor.PromEx.Plugins.RanchTest do
  use Supavisor.E2ECase, async: false

  alias Supavisor.PromEx.Plugins.Ranch

  @moduletag telemetry: true

  describe "polling_metrics/1" do
    test "properly exports metrics" do
      for polling_metric <- Ranch.polling_metrics([]) do
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
      for polling_metric <- Ranch.polling_metrics(poll_rate: 1000) do
        assert %{poll_rate: 1000} = polling_metric
      end
    end

    test "reports accepted and terminated as counters tagged by listener" do
      metrics =
        Ranch.polling_metrics([])
        |> Enum.flat_map(& &1.metrics)

      for suffix <- [:accepted, :terminated] do
        name = [:supavisor, :prom_ex, :ranch, :connections, suffix]
        metric = Enum.find(metrics, &(&1.name == name))

        assert metric, "expected a ranch #{suffix} metric named #{inspect(name)}"
        assert metric.reporter_options[:prometheus_type] == "counter"
        assert metric.tags == [:listener]
      end
    end
  end

  describe "execute_ranch_metrics/0" do
    test "emits one event per running listener with a listener tag" do
      ref = attach_handler([:supavisor, :prom_ex, :ranch])

      assert :ok = Ranch.execute_ranch_metrics()

      for {listener_ref, _pid} <- :ranch_server.get_listener_sups() do
        listener = Ranch.format_ref(listener_ref)

        assert_receive {^ref,
                        {[:supavisor, :prom_ex, :ranch], measurement, %{listener: ^listener}}}

        assert %{accepted: accepted, terminated: terminated} = measurement
        assert is_integer(accepted) and accepted >= 0
        assert is_integer(terminated) and terminated >= 0
        assert accepted >= terminated
      end
    end
  end

  describe "format_ref/1" do
    test "formats atom refs" do
      assert Ranch.format_ref(:pg_proxy) == "pg_proxy"
      assert Ranch.format_ref(:pg_proxy_session) == "pg_proxy_session"
    end

    test "formats internal shard refs" do
      assert Ranch.format_ref({:pg_proxy_internal, :session, 0}) == "pg_proxy_internal_session_0"

      assert Ranch.format_ref({:pg_proxy_internal, :transaction, 3}) ==
               "pg_proxy_internal_transaction_3"
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
