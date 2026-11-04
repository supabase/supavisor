defmodule Supavisor.PromEx.Plugins.EnaTest do
  use Supavisor.E2ECase, async: false

  alias Supavisor.PromEx.Plugins.Ena

  @moduletag telemetry: true

  @ethtool_fixture """
  NIC statistics:
       tx_timeout: 0
       suspend: 0
       bw_in_allowance_exceeded: 11
       bw_out_allowance_exceeded: 22
       pps_allowance_exceeded: 33
       conntrack_allowance_exceeded: 44
       linklocal_allowance_exceeded: 55
       conntrack_allowance_available: 136812
       queue_0_tx_cnt: 123456
  """

  @counters [
    :bw_in_allowance_exceeded,
    :bw_out_allowance_exceeded,
    :pps_allowance_exceeded,
    :conntrack_allowance_exceeded,
    :linklocal_allowance_exceeded
  ]

  describe "polling_metrics/1" do
    test "properly exports metrics" do
      for polling_metric <- Ena.polling_metrics(interface: "eth0") do
        assert %PromEx.MetricTypes.Polling{metrics: [_ | _]} = polling_metric
        assert {Ena, :execute_metrics, ["eth0"]} = polling_metric.measurements_mfa

        for telemetry_metric <- polling_metric.metrics do
          assert %Telemetry.Metrics.LastValue{} = telemetry_metric
          assert telemetry_metric.description
        end
      end
    end

    test "uses poll rate option" do
      for polling_metric <- Ena.polling_metrics(interface: "eth0", poll_rate: 1000) do
        assert %{poll_rate: 1000} = polling_metric
      end
    end

    test "reports allowance exceeded stats as counters" do
      metrics = Ena.polling_metrics(interface: "eth0") |> Enum.flat_map(& &1.metrics)

      for suffix <- @counters do
        name = [:supavisor, :prom_ex, :osmon, :ena, suffix]
        metric = Enum.find(metrics, &(&1.name == name))

        assert metric, "expected an ena #{suffix} metric named #{inspect(name)}"
        assert metric.reporter_options[:prometheus_type] == "counter"
      end
    end

    test "reports conntrack_allowance_available as a gauge" do
      metrics = Ena.polling_metrics(interface: "eth0") |> Enum.flat_map(& &1.metrics)
      name = [:supavisor, :prom_ex, :osmon, :ena, :conntrack_allowance_available]
      metric = Enum.find(metrics, &(&1.name == name))

      assert metric
      refute metric.reporter_options[:prometheus_type] == "counter"
    end

    test "measurements skip stats the driver does not report" do
      metrics = Ena.polling_metrics(interface: "eth0") |> Enum.flat_map(& &1.metrics)
      stats = %{bw_in_allowance_exceeded: 11}

      for metric <- metrics do
        expected =
          if metric.name == [:supavisor, :prom_ex, :osmon, :ena, :bw_in_allowance_exceeded],
            do: 11

        assert metric.measurement.(stats) == expected
      end
    end
  end

  describe "parse_ethtool_stats/1" do
    test "extracts allowance stats" do
      assert {:ok, stats} = Ena.parse_ethtool_stats(@ethtool_fixture)

      assert stats == %{
               bw_in_allowance_exceeded: 11,
               bw_out_allowance_exceeded: 22,
               pps_allowance_exceeded: 33,
               conntrack_allowance_exceeded: 44,
               linklocal_allowance_exceeded: 55,
               conntrack_allowance_available: 136_812
             }
    end

    test "omits stats the driver does not report" do
      content = """
      NIC statistics:
           bw_in_allowance_exceeded: 1
           pps_allowance_exceeded: 2
      """

      assert {:ok, %{bw_in_allowance_exceeded: 1, pps_allowance_exceeded: 2} = stats} =
               Ena.parse_ethtool_stats(content)

      assert map_size(stats) == 2
    end

    test "returns error for a non-ENA interface" do
      content = """
      NIC statistics:
           peer_ifindex: 4
           rx_queue_0_xdp_packets: 0
      """

      assert :error = Ena.parse_ethtool_stats(content)
    end

    test "returns error for empty content" do
      assert :error = Ena.parse_ethtool_stats("")
    end
  end

  describe "ethtool_stats/2" do
    test "passes the interface to ethtool -S" do
      ethtool = write_ethtool("[ \"$1\" = \"-S\" ] && [ \"$2\" = \"ens5\" ] || exit 1")

      assert {:ok, %{pps_allowance_exceeded: 33}} = Ena.ethtool_stats("ens5", ethtool)
      assert :error = Ena.ethtool_stats("eth0", ethtool)
    end

    test "returns error when ethtool is not installed" do
      assert :error = Ena.ethtool_stats("eth0", "/nonexistent/ethtool")
    end
  end

  describe "execute_metrics/2" do
    test "emits ena telemetry event" do
      ethtool = write_ethtool("true")
      ref = attach_handler([:supavisor, :prom_ex, :osmon, :ena])

      assert :ok = Ena.execute_metrics("eth0", ethtool)

      assert_receive {^ref, {[:supavisor, :prom_ex, :osmon, :ena], measurement, %{}}}

      assert %{bw_in_allowance_exceeded: 11, conntrack_allowance_available: 136_812} =
               measurement
    end

    test "returns ok and emits nothing when ethtool fails" do
      ethtool = write_ethtool("exit 1")
      ref = attach_handler([:supavisor, :prom_ex, :osmon, :ena])

      assert :ok = Ena.execute_metrics("eth0", ethtool)

      refute_receive {^ref, _}
    end
  end

  describe "Supavisor.Monitoring.PromEx.plugins/0" do
    setup do
      previous = Application.get_env(:supavisor, :ena_interface)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:supavisor, :ena_interface, previous),
          else: Application.delete_env(:supavisor, :ena_interface)
      end)
    end

    test "excludes the plugin when no interface is configured" do
      Application.delete_env(:supavisor, :ena_interface)

      refute Enum.any?(Supavisor.Monitoring.PromEx.plugins(), &match?({Ena, _}, &1))
    end

    test "includes the plugin with the configured interface" do
      Application.put_env(:supavisor, :ena_interface, "ens5")

      assert {Ena, opts} =
               Enum.find(Supavisor.Monitoring.PromEx.plugins(), &match?({Ena, _}, &1))

      assert opts[:interface] == "ens5"
    end
  end

  defp write_ethtool(guard) do
    path = Path.join(System.tmp_dir!(), "ethtool_fixture_#{:erlang.unique_integer([:positive])}")

    File.write!(path, """
    #!/bin/sh
    #{guard} || exit 1
    cat <<'EOF'
    #{@ethtool_fixture}
    EOF
    """)

    File.chmod!(path, 0o755)
    on_exit(fn -> File.rm(path) end)
    path
  end

  def handle_event(event_name, measurement, meta, {pid, ref}) do
    send(pid, {ref, {event_name, measurement, meta}})
  end

  defp attach_handler(event) do
    ref = make_ref()
    :telemetry.attach({ref, :test}, event, &__MODULE__.handle_event/4, {self(), ref})
    on_exit(fn -> :telemetry.detach({ref, :test}) end)
    ref
  end
end
