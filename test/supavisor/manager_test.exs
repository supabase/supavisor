defmodule Supavisor.ManagerTest do
  use ExUnit.Case, async: true

  require Supavisor

  @subject Supavisor.Manager

  @id Supavisor.id(
        type: :single,
        tenant: "manager_test",
        user: "postgres",
        mode: :transaction,
        db: "postgres"
      )

  # The Manager's state is a plain map, so the slot queue can be driven through the
  # callbacks directly. That keeps these tests off the database - the end-to-end behaviour
  # is covered by the integration tests.
  defp state(max_clients) do
    %{
      id: @id,
      tid: :ets.new(:clients, [:public, :set]),
      pid_to_ref: :ets.new(:pid_to_ref, [:public, :set]),
      mode: :transaction,
      pool_size: 10,
      max_clients: max_clients,
      parameter_status: [<<"S">>],
      idle_timeout: 0,
      wait_ps: [],
      terminating_error: nil,
      drain_caller: nil,
      drain_timer: nil,
      check_ref: Process.send_after(self(), :never, 60_000),
      slot_waiters: :queue.new(),
      slot_waiters_live: MapSet.new()
    }
  end

  defp idle_client do
    spawn(fn ->
      receive do
        :stop -> :ok
      end
    end)
  end

  defp subscribed_pids(state), do: state.tid |> :ets.tab2list() |> Enum.map(&elem(&1, 1))

  describe "request_slot/2 with room in the pool" do
    test "grants a slot immediately" do
      state = state(1)

      assert {:noreply, state} = @subject.handle_cast({:request_slot, self()}, state)

      assert subscribed_pids(state) == [self()]
      assert :queue.is_empty(state.slot_waiters)
      assert_received {:slot_granted, [<<"S">>], 0}
    end
  end

  describe "request_slot/2 on a full pool" do
    setup do
      state = state(1)
      holder = idle_client()
      {:noreply, state} = @subject.handle_cast({:request_slot, holder}, state)
      assert subscribed_pids(state) == [holder]

      %{state: state, holder: holder}
    end

    test "queues the client instead of granting or rejecting", ctx do
      waiter = idle_client()

      assert {:noreply, state} = @subject.handle_cast({:request_slot, waiter}, ctx.state)

      # Still only the original holder, and nothing was sent to the waiter.
      assert subscribed_pids(state) == [ctx.holder]
      assert :queue.len(state.slot_waiters) == 1
      assert MapSet.size(state.slot_waiters_live) == 1
    end

    test "grants the freed slot on unsubscribe", ctx do
      waiter = idle_client()
      {:noreply, state} = @subject.handle_cast({:request_slot, waiter}, ctx.state)

      assert {:reply, :ok, state} =
               @subject.handle_call({:unsubscribe, ctx.holder}, {self(), make_ref()}, state)

      assert subscribed_pids(state) == [waiter]
      assert :queue.is_empty(state.slot_waiters)
      assert MapSet.size(state.slot_waiters_live) == 0
    end

    test "grants the freed slot when a client dies", ctx do
      waiter = idle_client()
      {:noreply, state} = @subject.handle_cast({:request_slot, waiter}, ctx.state)

      [{holder_ref, _pid, _}] =
        :ets.tab2list(state.tid) |> Enum.filter(&(elem(&1, 1) == ctx.holder))

      assert {:noreply, state} =
               @subject.handle_info({:DOWN, holder_ref, :process, ctx.holder, :normal}, state)

      assert subscribed_pids(state) == [waiter]
    end

    test "grants in request order", ctx do
      first = idle_client()
      second = idle_client()
      {:noreply, state} = @subject.handle_cast({:request_slot, first}, ctx.state)
      {:noreply, state} = @subject.handle_cast({:request_slot, second}, state)

      assert {:reply, :ok, state} =
               @subject.handle_call({:unsubscribe, ctx.holder}, {self(), make_ref()}, state)

      assert subscribed_pids(state) == [first]
      assert :queue.len(state.slot_waiters) == 1
    end

    test "skips a waiter that gave up and grants to the next one", ctx do
      gave_up = idle_client()
      still_waiting = idle_client()
      {:noreply, state} = @subject.handle_cast({:request_slot, gave_up}, ctx.state)
      {:noreply, state} = @subject.handle_cast({:request_slot, still_waiting}, state)

      [gave_up_mon] =
        state.slot_waiters
        |> :queue.to_list()
        |> Enum.filter(fn {_mon, pid} -> pid == gave_up end)
        |> Enum.map(&elem(&1, 0))

      # A waiter that terminates is withdrawn by its monitor, and holds no slot to release.
      assert {:noreply, state} =
               @subject.handle_info({:DOWN, gave_up_mon, :process, gave_up, :normal}, state)

      assert subscribed_pids(state) == [ctx.holder]

      assert {:reply, :ok, state} =
               @subject.handle_call({:unsubscribe, ctx.holder}, {self(), make_ref()}, state)

      assert subscribed_pids(state) == [still_waiting]
    end

    test "tells the waiter once its slot is granted", ctx do
      {:noreply, state} = @subject.handle_cast({:request_slot, self()}, ctx.state)
      refute_received {:slot_granted, _ps, _idle}

      assert {:reply, :ok, _state} =
               @subject.handle_call({:unsubscribe, ctx.holder}, {self(), make_ref()}, state)

      assert_received {:slot_granted, [<<"S">>], 0}
    end

    test "denies the request when the pool is shutting down", ctx do
      state = %{ctx.state | terminating_error: %{"M" => "shutting down"}}

      assert {:noreply, state} = @subject.handle_cast({:request_slot, self()}, state)

      assert :queue.is_empty(state.slot_waiters)
      assert_received {:slot_denied, %Supavisor.Errors.PoolTerminatingError{}}
    end
  end
end
