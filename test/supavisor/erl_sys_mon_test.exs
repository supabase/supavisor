defmodule Supavisor.ErlSysMonTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  alias Supavisor.ErlSysMon

  test "starts and configures monitor with custom name" do
    assert {:ok, pid} = ErlSysMon.start_link(name: __MODULE__)
    assert Process.whereis(__MODULE__) == pid

    {monitor_pid, settings} = :erlang.system_monitor()
    assert monitor_pid == pid

    [
      :busy_dist_port,
      :busy_port,
      {:long_gc, 250},
      {:long_schedule, 100},
      {:large_heap, 3_276_800}
    ]
    |> Enum.each(&assert &1 in settings)

    test_msg = {:monitor, self(), :test_pid, :busy_port}

    log =
      capture_log(fn ->
        send(pid, test_msg)
        Process.sleep(100)
      end)

    assert log =~ "Supavisor.ErlSysMon message:"
    assert log =~ inspect(test_msg)

    Process.exit(pid, :normal)
  end

  test "starts with default name when no args provided" do
    pid = Process.whereis(ErlSysMon)
    assert is_pid(pid)
    assert Process.alive?(pid)

    assert {:error, {:already_started, ^pid}} = ErlSysMon.start_link([])
  end
end
