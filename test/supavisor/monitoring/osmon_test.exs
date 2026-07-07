defmodule Supavisor.PromEx.Plugins.OsMonTest do
  use Supavisor.E2ECase, async: false

  alias Supavisor.PromEx.Plugins.OsMon

  @moduletag telemetry: true

  @netstat_fixture """
  TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPPrequeued TCPDirectCopyFromBacklog TCPDirectCopyFromPrequeue TCPPrequeueDropped TCPHPHits TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSchedulerFailed TCPRcvCollapsed TCPBacklogCoalesce TCPDSACKOldSent TCPDSACKOfoSent TCPDSACKRecv TCPDSACKOfoRecv TCPAbortOnData TCPAbortOnClose TCPAbortOnMemory TCPAbortOnTimeout TCPAbortOnLinger TCPAbortFailed TCPMemoryPressures TCPMemoryPressuresChrono TCPSACKDiscard TCPDSACKIgnoredOld TCPDSACKIgnoredNoUndo TCPSpuriousRTOs TCPMD5NotFound TCPMD5Unexpected TCPMD5Failure TCPSackShifted TCPSackMerged TCPSackShiftFallback TCPBacklogDrop TCPMinTTLDrop TCPDeferAcceptDrop IPReversePathFilter TCPTimeWaitOverflow TCPReqQFullDoCookies TCPReqQFullDrop TCPRetransFail TCPSchedulerFailed2
  TcpExt: 0 0 0 0 0 0 0 0 0 0 1234 0 0 0 567 89012 345 678 42 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
  IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors InNoECTPkts InECT1Pkts InECT0Pkts InCEPkts ReasmOverlaps
  IpExt: 0 0 0 0 0 0 123456789 987654321 0 0 0 0 0 0 0 0 0 0
  """

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

  describe "parse_net_stat/1" do
    test "extracts ListenDrops and ListenOverflows" do
      assert {:ok, %{listen_drops: 17, listen_overflows: 42}} =
               OsMon.parse_net_stat(@netstat_fixture)
    end

    test "defaults missing counters to 0" do
      content = """
      TcpExt: SyncookiesSent
      TcpExt: 0
      """

      assert {:ok, %{listen_drops: 0, listen_overflows: 0}} = OsMon.parse_net_stat(content)
    end

    test "returns error for empty content" do
      assert :error = OsMon.parse_net_stat("")
    end

    test "returns error when TcpExt section is missing" do
      content = """
      IpExt: InNoRoutes InTruncatedPkts
      IpExt: 0 0
      """

      assert :error = OsMon.parse_net_stat(content)
    end
  end

  describe "net_stat/1" do
    @tag :linux
    test "reads real /proc/net/netstat on linux" do
      assert {:ok, %{listen_drops: drops, listen_overflows: overflows}} = OsMon.net_stat()
      assert is_integer(drops)
      assert is_integer(overflows)
    end
  end

  describe "execute_net_stat_metrics/1" do
    test "emits net_stat telemetry event when file exists" do
      path = write_netstat_fixture(@netstat_fixture)
      ref = attach_handler([:supavisor, :prom_ex, :osmon, :net_stat])

      assert :ok = OsMon.execute_net_stat_metrics(path)

      assert_receive {^ref, {[:supavisor, :prom_ex, :osmon, :net_stat], measurement, %{}}}
      assert %{listen_drops: 17, listen_overflows: 42} = measurement
    end

    test "returns ok and emits nothing when file does not exist" do
      assert :ok = OsMon.execute_net_stat_metrics("/nonexistent/path")
    end
  end

  defp write_netstat_fixture(content) do
    path = Path.join(System.tmp_dir!(), "netstat_#{:erlang.unique_integer([:positive])}")
    File.write!(path, content)
    on_exit(fn -> File.rm(path) end)
    path
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
