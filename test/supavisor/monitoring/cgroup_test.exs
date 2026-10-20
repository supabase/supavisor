defmodule Supavisor.PromEx.Plugins.CGroupTest do
  use Supavisor.E2ECase, async: false

  alias Supavisor.PromEx.Plugins.CGroup

  @moduletag telemetry: true

  describe "polling_metrics/1" do
    test "properly exports metrics" do
      for polling_metric <- CGroup.polling_metrics([]) do
        assert %PromEx.MetricTypes.Polling{metrics: [_ | _]} = polling_metric
        {m, f, a} = polling_metric.measurements_mfa
        assert function_exported?(m, f, length(a))

        for telemetry_metric <- polling_metric.metrics do
          assert %Telemetry.Metrics.LastValue{} = telemetry_metric
          assert telemetry_metric.description
        end
      end
    end

    test "uses poll rate option" do
      for polling_metric <- CGroup.polling_metrics(poll_rate: 1000) do
        assert %{poll_rate: 1000} = polling_metric
      end
    end

    test "reports memory_current and memory_max gauges" do
      metrics =
        CGroup.polling_metrics([])
        |> Enum.flat_map(& &1.metrics)

      for suffix <- [:memory_current, :memory_max] do
        name = [:supavisor, :prom_ex, :osmon, :cgroup, suffix]
        assert Enum.find(metrics, &(&1.name == name)), "expected a cgroup #{suffix} metric"
      end
    end
  end

  describe "memory/2" do
    test "reads current usage and limit" do
      current_path = write_fixture("104857600\n")
      max_path = write_fixture("2147483648\n")

      assert {:ok, %{memory_current: 104_857_600, memory_max: 2_147_483_648}} =
               CGroup.memory(current_path, max_path)
    end

    test "reports the unlimited sentinel when the cgroup has no memory limit" do
      current_path = write_fixture("104857600\n")
      max_path = write_fixture("max\n")

      assert {:ok, stats} = CGroup.memory(current_path, max_path)
      assert stats.memory_current == 104_857_600
      assert stats.memory_max == CGroup.unlimited_memory()
    end

    test "reports the unlimited sentinel when the max file is missing" do
      current_path = write_fixture("104857600\n")

      assert {:ok, stats} = CGroup.memory(current_path, "/nonexistent/path")
      assert stats.memory_current == 104_857_600
      assert stats.memory_max == CGroup.unlimited_memory()
    end

    test "returns error when the current file is missing" do
      max_path = write_fixture("2147483648\n")

      assert :error = CGroup.memory("/nonexistent/path", max_path)
    end

    test "returns error when the current file is not an integer" do
      current_path = write_fixture("not a number\n")
      max_path = write_fixture("2147483648\n")

      assert :error = CGroup.memory(current_path, max_path)
    end
  end

  describe "memory/0" do
    @tag :linux
    test "self-discovers the cgroup and reads real memory.current on linux" do
      case CGroup.memory() do
        {:ok, %{memory_current: current}} -> assert is_integer(current)
        :error -> :ok
      end
    end

    @tag :linux
    test "reuses the cached cgroup directory on repeated calls" do
      first = CGroup.memory()
      second = CGroup.memory()

      case {first, second} do
        {{:ok, _}, {:ok, _}} -> :ok
        {:error, :error} -> :ok
        _ -> flunk("expected both calls to agree on whether the cgroup could be resolved")
      end
    end
  end

  describe "parse_cgroup_path/1" do
    test "extracts the cgroup v2 unified path" do
      assert {:ok, "system.slice/supavisor.service"} =
               CGroup.parse_cgroup_path("0::/system.slice/supavisor.service\n")
    end

    test "extracts the root path as empty" do
      assert {:ok, ""} = CGroup.parse_cgroup_path("0::/\n")
    end

    test "finds the 0:: entry even when other hierarchy lines precede it" do
      content = """
      1:memory:/system.slice/supavisor.service
      0::other
      """

      assert {:ok, "other"} = CGroup.parse_cgroup_path(content)
    end

    test "returns error when there is no 0:: unified entry" do
      content = """
      1:memory:/system.slice/supavisor.service
      """

      assert :error = CGroup.parse_cgroup_path(content)
    end

    test "returns error for empty content" do
      assert :error = CGroup.parse_cgroup_path("")
    end
  end

  describe "cgroup_dir/2" do
    test "joins the resolved relative path onto the cgroup root" do
      proc_cgroup_path = write_fixture("0::/system.slice/supavisor.service\n")

      assert {:ok, "/sys/fs/cgroup/system.slice/supavisor.service"} =
               CGroup.cgroup_dir(proc_cgroup_path, "/sys/fs/cgroup")
    end

    test "returns error when the proc cgroup file does not exist" do
      assert :error = CGroup.cgroup_dir("/nonexistent/path", "/sys/fs/cgroup")
    end

    @tag :linux
    test "self-discovers a real cgroup directory on linux" do
      assert {:ok, dir} = CGroup.cgroup_dir()
      assert String.starts_with?(dir, "/sys/fs/cgroup")
    end
  end

  describe "exported metric value (real Peep storage pipeline)" do
    test "memory_max is stored as the unlimited sentinel, not Peep's default-missing-key value of 1" do
      peep_name = :"cgroup_peep_test_#{System.unique_integer([:positive])}"
      metrics = CGroup.polling_metrics([]) |> Enum.flat_map(& &1.metrics)
      start_supervised!({Peep, name: peep_name, metrics: metrics})

      current_path = write_fixture("104857600\n")
      max_path = write_fixture("max\n")

      assert :ok = CGroup.execute_memory_metrics(current_path, max_path)

      memory_max_metric =
        Enum.find(metrics, &(&1.name == [:supavisor, :prom_ex, :osmon, :cgroup, :memory_max]))

      assert %{} = values = Peep.get_all_metrics(peep_name) |> Map.fetch!(memory_max_metric)
      assert [{_tags, value}] = Map.to_list(values)
      assert value == CGroup.unlimited_memory()
      refute value == 1
    end
  end

  describe "execute_memory_metrics/0" do
    test "covers the production entrypoint end-to-end via a faked cached cgroup dir" do
      dir =
        Path.join(System.tmp_dir!(), "cgroup_fixture_dir_#{System.unique_integer([:positive])}")

      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "memory.current"), "104857600\n")
      File.write!(Path.join(dir, "memory.max"), "max\n")

      on_exit(fn ->
        :persistent_term.erase({CGroup, :cgroup_dir})
        File.rm_rf!(dir)
      end)

      :persistent_term.put({CGroup, :cgroup_dir}, {:ok, dir})

      ref = attach_handler([:supavisor, :prom_ex, :osmon, :cgroup_memory])

      assert :ok = CGroup.execute_memory_metrics()

      assert_receive {^ref, {[:supavisor, :prom_ex, :osmon, :cgroup_memory], measurement, %{}}}
      assert %{memory_current: 104_857_600, memory_max: memory_max} = measurement
      assert memory_max == CGroup.unlimited_memory()
    end
  end

  describe "execute_memory_metrics/2" do
    test "emits cgroup_memory telemetry event when files exist" do
      current_path = write_fixture("104857600\n")
      max_path = write_fixture("2147483648\n")
      ref = attach_handler([:supavisor, :prom_ex, :osmon, :cgroup_memory])

      assert :ok = CGroup.execute_memory_metrics(current_path, max_path)

      assert_receive {^ref, {[:supavisor, :prom_ex, :osmon, :cgroup_memory], measurement, %{}}}
      assert %{memory_current: 104_857_600, memory_max: 2_147_483_648} = measurement
    end

    test "returns ok and emits nothing when the current file does not exist" do
      assert :ok = CGroup.execute_memory_metrics("/nonexistent/path", "/nonexistent/path")
    end
  end

  defp write_fixture(content) do
    path = Path.join(System.tmp_dir!(), "cgroup_fixture_#{:erlang.unique_integer([:positive])}")
    File.write!(path, content)
    on_exit(fn -> File.rm(path) end)
    path
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
