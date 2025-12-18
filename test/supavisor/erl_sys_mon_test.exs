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
      {:long_gc, 500},
      {:long_schedule, 500},
      {:long_message_queue, {0, 1_000}},
      {:large_heap, 3_276_800}
    ]
    |> Enum.each(&assert &1 in settings)

    victim_pid = start_supervised!({Agent, fn -> :ok end}, id: :test_victim)
    Process.register(victim_pid, :test_victim)

    msg =
      {:monitor, victim_pid, :long_message_queue,
       [message_queue_len: 5000, current_function: {:gen_server, :loop, 3}]}

    log =
      capture_log(fn ->
        send(pid, msg)
        Process.sleep(100)
      end)

    assert log =~ "Alert: :long_message_queue"
    assert log =~ "PID: #{inspect(victim_pid)}"
    assert log =~ "Process: :test_victim"
    assert log =~ "message_queue_len: 5000"
    assert log =~ "current_function:"
    assert log =~ ":gen_server"
    assert log =~ "Message queue length: 0"
    assert log =~ "Total heap size:"
    assert log =~ "MB"
    assert log =~ "Stacktrace:"

    Process.exit(pid, :normal)
  end

  test "starts with default name when no args provided" do
    pid = Process.whereis(ErlSysMon)
    assert is_pid(pid)
    assert Process.alive?(pid)

    assert {:error, {:already_started, ^pid}} = ErlSysMon.start_link([])
  end
end
