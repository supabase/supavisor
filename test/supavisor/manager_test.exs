defmodule Supavisor.ManagerTest do
  use ExUnit.Case, async: true

  @subject Supavisor.Manager

  describe "code_change/3" do
    test "creates pid_to_ref table from existing tid entries" do
      tid = :ets.new(:test_tid, [:protected])
      ref1 = make_ref()
      ref2 = make_ref()
      pid1 = self()
      pid2 = start_supervised!({Task, fn -> :timer.sleep(:infinity) end})

      :ets.insert(tid, {ref1, pid1, 1_000})
      :ets.insert(tid, {ref2, pid2, 2_000})

      old_state = %{tid: tid}

      assert {:ok, new_state} =
               @subject.code_change("1.0", old_state, :create_pid_to_ref_table)

      assert [{^pid1, ^ref1}] = :ets.lookup(new_state.pid_to_ref, pid1)
      assert [{^pid2, ^ref2}] = :ets.lookup(new_state.pid_to_ref, pid2)
      assert new_state.waiting_for_secrets == []
    end

    test "catch-all clause returns state unchanged" do
      state = %{tid: :some_tid, pid_to_ref: :some_table}

      assert {:ok, ^state} = @subject.code_change("1.0", state, [])
    end
  end
end
