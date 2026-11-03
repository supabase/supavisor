defmodule Supavisor.PromEx.Plugins.OsMonTest do
  use Supavisor.E2ECase, async: false

  import ExUnit.CaptureLog

  alias Supavisor.PromEx.Plugins.OsMon

  @moduletag telemetry: true

  describe "polling_metrics/1" do
    test "properly exports metrics" do
      for polling_metric <- OsMon.polling_metrics([]) do
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
      for polling_metric <- OsMon.polling_metrics(poll_rate: 1000) do
        assert %{poll_rate: 1000} = polling_metric
      end
    end
  end

  describe "log_if_high_ram/2" do
    @ten_minutes :timer.minutes(10)

    setup do
      on_exit(fn ->
        Application.delete_env(:supavisor, :high_ram_usage_percent)
        Application.delete_env(:supavisor, :high_ram_usage_duration_ms)
      end)
    end

    test "warns once at or above 80% for 10 minutes" do
      log =
        capture_log(fn ->
          OsMon.log_if_high_ram(85.0, 0)
          OsMon.log_if_high_ram(85.0, @ten_minutes - 1)
        end)

      refute log =~ "High RAM usage"

      log = capture_log(fn -> OsMon.log_if_high_ram(85.04, @ten_minutes) end)

      assert log =~ "High RAM usage: 85.0% (at or above 80%) for 600s"
    end

    test "warns at exactly the configured percent" do
      log =
        capture_log(fn ->
          OsMon.log_if_high_ram(80.0, 0)
          OsMon.log_if_high_ram(80.0, @ten_minutes)
        end)

      assert log =~ "High RAM usage: 80.0%"
    end

    test "dropping below the percent resets the timer" do
      log =
        capture_log(fn ->
          OsMon.log_if_high_ram(85.0, 0)
          OsMon.log_if_high_ram(79.9, 1_000)
          OsMon.log_if_high_ram(85.0, @ten_minutes)
        end)

      refute log =~ "High RAM usage"
    end

    test "honors configured percent and duration" do
      Application.put_env(:supavisor, :high_ram_usage_percent, 55.0)
      Application.put_env(:supavisor, :high_ram_usage_duration_ms, 1_000)

      log =
        capture_log(fn ->
          OsMon.log_if_high_ram(55.0, 0)
          OsMon.log_if_high_ram(55.0, 1_000)
        end)

      assert log =~ "(at or above 55.0%)"
    end
  end

  describe "disk metric definitions" do
    test "defines total/available/used_percent tagged by mountpoint" do
      metrics =
        OsMon.polling_metrics([])
        |> Enum.flat_map(& &1.metrics)

      for suffix <- [:total, :available, :used_percent] do
        name = [:supavisor, :prom_ex, :osmon, :disk, suffix]
        metric = Enum.find(metrics, &(&1.name == name))

        assert metric, "expected a disk #{suffix} metric named #{inspect(name)}"
        assert metric.tags == [:mountpoint]
      end
    end
  end

  describe "disk/0" do
    test "returns byte totals and capacity per mountpoint" do
      assert [_ | _] = disks = OsMon.disk()

      for {mountpoint, measurements} <- disks do
        assert is_binary(mountpoint)

        assert %{total: total, available: available, capacity: capacity} = measurements
        assert is_integer(total) and total >= 0
        assert is_integer(available) and available >= 0
        assert available <= total
        assert capacity in 0..100
      end
    end
  end

  describe "execute_disk_metrics/0" do
    test "emits a disk event per filesystem, each tagged with its mountpoint" do
      ref = attach_handler([:prom_ex, :plugin, :osmon, :disk])

      assert :ok = OsMon.execute_disk_metrics()

      events = drain_events(ref)
      assert events != []

      for {measurement, meta} <- events do
        assert %{total: total, available: available, capacity: capacity} = measurement
        assert is_integer(total)
        assert is_integer(available)
        assert capacity in 0..100

        assert %{mountpoint: mountpoint} = meta
        assert is_binary(mountpoint)
      end

      received = MapSet.new(events, fn {_measurement, meta} -> meta.mountpoint end)
      expected = MapSet.new(OsMon.disk(), fn {mountpoint, _} -> mountpoint end)
      assert MapSet.subset?(expected, received)
    end
  end

  def handle_event(event_name, measurement, meta, {pid, ref}) do
    send(pid, {ref, {event_name, measurement, meta}})
  end

  defp drain_events(ref, acc \\ []) do
    receive do
      {^ref, {[:prom_ex, :plugin, :osmon, :disk], measurement, meta}} ->
        drain_events(ref, [{measurement, meta} | acc])
    after
      100 -> Enum.reverse(acc)
    end
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
