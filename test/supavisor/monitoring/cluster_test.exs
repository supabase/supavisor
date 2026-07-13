defmodule Supavisor.PromEx.Plugins.ClusterTest do
  use Supavisor.E2ECase, async: false

  alias Supavisor.PromEx.Plugins.Cluster

  @moduletag telemetry: true

  describe "polling_metrics/1" do
    test "properly exports metrics" do
      for polling_metric <- Cluster.polling_metrics([]) do
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
      for polling_metric <- Cluster.polling_metrics(poll_rate: 1000) do
        assert %{poll_rate: 1000} = polling_metric
      end
    end
  end

  describe "manual_metrics/1" do
    test "properly exports metrics" do
      for manual_metric <- Cluster.manual_metrics([]) do
        assert %PromEx.MetricTypes.Manual{metrics: [_ | _]} = manual_metric
        {m, f, a} = manual_metric.measurements_mfa
        assert function_exported?(m, f, length(a))

        for telemetry_metric <- manual_metric.metrics do
          assert is_struct(telemetry_metric, Telemetry.Metrics.LastValue)
          assert telemetry_metric.description
        end
      end
    end
  end

  describe "emit_cluster_size/0" do
    test "emits cluster size event" do
      ref = attach_handler([:supavisor, :prom_ex, :cluster])
      assert :ok = Cluster.emit_cluster_size()

      assert_receive {^ref, {[:supavisor, :prom_ex, :cluster], measurement, meta}}

      assert %{size: size} = measurement
      assert is_integer(size)
      assert size >= 1
      assert meta == %{}
    end
  end

  describe "emit_app_version/0" do
    test "emits application version event" do
      ref = attach_handler([:supavisor, :prom_ex, :application, :version])
      expected_current = Application.spec(:supavisor, :vsn) |> to_string()
      assert :ok = Cluster.emit_app_version()

      assert_receive {^ref, {[:supavisor, :prom_ex, :application, :version], measurement, meta}}

      assert %{status: 1} = measurement

      assert %{
               current: ^expected_current,
               # this is set to the OTP version in the test env
               permanent: _permanent,
               base: "",
               previous: ""
             } = meta
    end
  end

  describe "emit_ami_version/0" do
    test "emits AMI version event from AMI_VERSION env var" do
      ref = attach_handler([:supavisor, :prom_ex, :ami, :version])

      System.put_env("AMI_VERSION", "2024.01.01")
      on_exit(fn -> System.delete_env("AMI_VERSION") end)

      assert :ok = Cluster.emit_ami_version()

      assert_receive {^ref, {[:supavisor, :prom_ex, :ami, :version], measurement, meta}}

      assert %{status: 1} = measurement
      assert %{version: "2024.01.01"} = meta
    end

    test "does not emit when AMI_VERSION is unset" do
      ref = attach_handler([:supavisor, :prom_ex, :ami, :version])

      System.delete_env("AMI_VERSION")

      assert :ok = Cluster.emit_ami_version()

      refute_receive {^ref, {[:supavisor, :prom_ex, :ami, :version], _measurement, _meta}}
    end

    test "does not emit when AMI_VERSION is empty" do
      ref = attach_handler([:supavisor, :prom_ex, :ami, :version])

      System.put_env("AMI_VERSION", "")
      on_exit(fn -> System.delete_env("AMI_VERSION") end)

      assert :ok = Cluster.emit_ami_version()

      refute_receive {^ref, {[:supavisor, :prom_ex, :ami, :version], _measurement, _meta}}
    end
  end

  describe "emit_erpc_latency/0" do
    test "emits ERPC latency events for all nodes" do
      ref = attach_handler([:supavisor, :prom_ex, :cluster, :erpc_ping, :stop])

      assert :ok = Cluster.emit_erpc_latency()

      # Should receive at least one event for the current node
      assert_receive {^ref,
                      {[:supavisor, :prom_ex, :cluster, :erpc_ping, :stop], measurement, meta}}

      assert %{duration: duration} = measurement
      assert is_integer(duration)
      assert duration >= 0

      assert %{target_node: target_node, result: result} = meta
      assert is_atom(target_node)
      assert result in [:success, :failure]
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
