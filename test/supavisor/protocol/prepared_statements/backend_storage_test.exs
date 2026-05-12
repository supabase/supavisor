defmodule Supavisor.Protocol.PreparedStatements.BackendStorageTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Supavisor.Protocol.PreparedStatements.BackendStorage

  describe "new/0" do
    test "is empty" do
      storage = BackendStorage.new()

      assert BackendStorage.size(storage) == 0
      refute BackendStorage.member?(storage, "stmt_1")
    end
  end

  describe "put/2" do
    test "registers a statement" do
      storage = BackendStorage.new() |> BackendStorage.put("stmt_1")

      assert BackendStorage.size(storage) == 1
      assert BackendStorage.member?(storage, "stmt_1")
    end

    test "re-putting an existing statement keeps size and refreshes recency" do
      storage =
        BackendStorage.new()
        |> BackendStorage.put("stmt_1")
        |> BackendStorage.put("stmt_2")
        |> BackendStorage.put("stmt_1")

      assert BackendStorage.size(storage) == 2

      {[oldest], _} = BackendStorage.pop_oldest(storage, 1)
      assert oldest == "stmt_2"
    end
  end

  describe "touch/2" do
    test "refreshes recency of an existing statement" do
      storage =
        BackendStorage.new()
        |> BackendStorage.put("stmt_1")
        |> BackendStorage.put("stmt_2")
        |> BackendStorage.touch("stmt_1")

      {[oldest], _} = BackendStorage.pop_oldest(storage, 1)
      assert oldest == "stmt_2"
    end

    test "is a no-op for an unknown statement" do
      storage = BackendStorage.new() |> BackendStorage.put("stmt_1")
      touched = BackendStorage.touch(storage, "stmt_unknown")

      assert touched == storage
    end
  end

  describe "delete/2" do
    test "removes a statement" do
      storage =
        BackendStorage.new()
        |> BackendStorage.put("stmt_1")
        |> BackendStorage.put("stmt_2")
        |> BackendStorage.delete("stmt_1")

      assert BackendStorage.size(storage) == 1
      refute BackendStorage.member?(storage, "stmt_1")
      assert BackendStorage.member?(storage, "stmt_2")
    end

    test "deleting an unknown statement is a no-op" do
      storage = BackendStorage.new() |> BackendStorage.put("stmt_1")
      after_delete = BackendStorage.delete(storage, "stmt_unknown")

      assert after_delete == storage
    end
  end

  describe "pop_oldest/2" do
    test "returns oldest names in order of recency" do
      storage =
        Enum.reduce(1..5, BackendStorage.new(), fn i, acc ->
          BackendStorage.put(acc, "stmt_#{i}")
        end)

      {evicted, remaining} = BackendStorage.pop_oldest(storage, 2)

      assert evicted == ["stmt_1", "stmt_2"]
      assert BackendStorage.size(remaining) == 3
      refute BackendStorage.member?(remaining, "stmt_1")
      refute BackendStorage.member?(remaining, "stmt_2")
      assert BackendStorage.member?(remaining, "stmt_5")
    end

    test "respects recency updated by touch" do
      storage =
        BackendStorage.new()
        |> BackendStorage.put("stmt_1")
        |> BackendStorage.put("stmt_2")
        |> BackendStorage.put("stmt_3")
        |> BackendStorage.touch("stmt_1")

      {evicted, _} = BackendStorage.pop_oldest(storage, 1)
      assert evicted == ["stmt_2"]
    end

    test "n greater than size returns all and empties storage" do
      storage =
        BackendStorage.new()
        |> BackendStorage.put("stmt_1")
        |> BackendStorage.put("stmt_2")

      {evicted, remaining} = BackendStorage.pop_oldest(storage, 10)

      assert evicted == ["stmt_1", "stmt_2"]
      assert BackendStorage.size(remaining) == 0
    end

    test "returns empty list when storage is empty" do
      {evicted, remaining} = BackendStorage.pop_oldest(BackendStorage.new(), 5)

      assert evicted == []
      assert BackendStorage.size(remaining) == 0
    end
  end

  describe "LRU invariant" do
    @names ~w(stmt_a stmt_b stmt_c stmt_d stmt_e)

    property "pop_oldest returns names ordered by last put/touch across arbitrary op sequences" do
      check all ops <- list_of(operation(), max_length: 50) do
        {storage, expected_order} = simulate(ops)
        actual_order = pop_all_in_order(storage)

        assert actual_order == expected_order
      end
    end

    defp operation do
      one_of([
        tuple({constant(:put), member_of(@names)}),
        tuple({constant(:touch), member_of(@names)}),
        tuple({constant(:delete), member_of(@names)})
      ])
    end

    defp simulate(ops) do
      {storage, _seq, shadow} =
        Enum.reduce(ops, {BackendStorage.new(), 0, %{}}, &apply_op/2)

      expected =
        shadow
        |> Enum.sort_by(fn {_name, seq} -> seq end)
        |> Enum.map(fn {name, _seq} -> name end)

      {storage, expected}
    end

    defp apply_op({:put, name}, {storage, seq, shadow}) do
      {BackendStorage.put(storage, name), seq + 1, Map.put(shadow, name, seq + 1)}
    end

    defp apply_op({:touch, name}, {storage, seq, shadow}) do
      if Map.has_key?(shadow, name) do
        {BackendStorage.touch(storage, name), seq + 1, Map.put(shadow, name, seq + 1)}
      else
        {BackendStorage.touch(storage, name), seq, shadow}
      end
    end

    defp apply_op({:delete, name}, {storage, seq, shadow}) do
      {BackendStorage.delete(storage, name), seq, Map.delete(shadow, name)}
    end

    defp pop_all_in_order(storage) do
      case BackendStorage.size(storage) do
        0 -> []
        size -> storage |> BackendStorage.pop_oldest(size) |> elem(0)
      end
    end
  end
end
