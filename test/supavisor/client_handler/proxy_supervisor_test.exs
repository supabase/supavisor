defmodule Supavisor.ClientHandler.ProxySupervisorTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler.{ProxySupervisor, ProxySupervisorWatchdog}

  @registry Supavisor.Registry.Tenants

  defp unique_id,
    do: {{:single, "test_#{System.unique_integer([:positive])}"}, "user", :transaction, "db", nil}

  defp start_proxy_supervisor(id, max_clients) do
    # Use a very long check interval so the timer never fires — tests use check_now/1 instead.
    start_supervised!(
      {ProxySupervisor,
       [id: id, max_clients: max_clients, watchdog_opts: [check_interval: :timer.hours(1)]]}
    )
  end

  defp fake_child_spec do
    %{
      id: make_ref(),
      start: {Agent, :start_link, [fn -> :ok end]},
      restart: :temporary
    }
  end

  describe "max_children enforcement" do
    test "allows starting children up to max_clients" do
      id = unique_id()
      start_proxy_supervisor(id, 3)

      assert {:ok, _} = ProxySupervisor.start_connection(id, fake_child_spec())
      assert {:ok, _} = ProxySupervisor.start_connection(id, fake_child_spec())
      assert {:ok, _} = ProxySupervisor.start_connection(id, fake_child_spec())
    end

    test "rejects children beyond max_clients" do
      id = unique_id()
      start_proxy_supervisor(id, 2)

      assert {:ok, _} = ProxySupervisor.start_connection(id, fake_child_spec())
      assert {:ok, _} = ProxySupervisor.start_connection(id, fake_child_spec())
      assert {:error, :max_children} = ProxySupervisor.start_connection(id, fake_child_spec())
    end

    test "allows new children after existing ones terminate" do
      id = unique_id()
      start_proxy_supervisor(id, 1)

      assert {:ok, pid} = ProxySupervisor.start_connection(id, fake_child_spec())
      assert {:error, :max_children} = ProxySupervisor.start_connection(id, fake_child_spec())

      Agent.stop(pid)

      assert {:ok, _} = ProxySupervisor.start_connection(id, fake_child_spec())
    end
  end

  describe "watchdog shutdown" do
    test "shuts down after two consecutive empty checks" do
      id = unique_id()
      sup = start_proxy_supervisor(id, 2)
      watchdog = ProxySupervisor.get_watchdog(sup)

      [{dyn_sup, _}] = Registry.lookup(@registry, {:proxy_dyn_sup, id})
      dyn_sup_ref = Process.monitor(dyn_sup)

      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)
      assert :stopping = ProxySupervisorWatchdog.check_now(watchdog)

      assert_receive {:DOWN, ^dyn_sup_ref, :process, ^dyn_sup, _}, 1_000
      Process.sleep(100)
      assert Registry.lookup(@registry, {:proxy_dyn_sup, id}) == []
    end

    test "does not shut down while children exist" do
      id = unique_id()
      sup = start_proxy_supervisor(id, 2)
      watchdog = ProxySupervisor.get_watchdog(sup)

      {:ok, child} = ProxySupervisor.start_connection(id, fake_child_spec())

      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)
      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)
      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)
      assert Process.alive?(sup)

      # Stop the child — now it should shut down after two checks
      Agent.stop(child)
      ref = Process.monitor(sup)

      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)
      assert :stopping = ProxySupervisorWatchdog.check_now(watchdog)

      assert_receive {:DOWN, ^ref, :process, ^sup, _}, 1_000
    end

    test "resets empty check counter when a child appears between checks" do
      id = unique_id()
      sup = start_proxy_supervisor(id, 2)
      watchdog = ProxySupervisor.get_watchdog(sup)

      # First empty check
      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)

      # Start a child — should reset counter
      {:ok, child} = ProxySupervisor.start_connection(id, fake_child_spec())
      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)

      # Stop the child — counter was reset, so needs two more empty checks
      Agent.stop(child)
      assert :alive = ProxySupervisorWatchdog.check_now(watchdog)
      assert Process.alive?(sup)

      # Second consecutive empty check — now it shuts down
      ref = Process.monitor(sup)
      assert :stopping = ProxySupervisorWatchdog.check_now(watchdog)
      assert_receive {:DOWN, ^ref, :process, ^sup, _}, 1_000
    end
  end
end
