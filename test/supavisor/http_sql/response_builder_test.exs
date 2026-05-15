defmodule Supavisor.HttpSql.ResponseBuilderTest do
  use ExUnit.Case, async: true

  @subject Supavisor.HttpSql.ResponseBuilder

  defp q(columns, oids) do
    %Postgrex.Query{columns: columns, result_oids: oids, result_formats: List.duplicate(:binary, length(oids))}
  end

  defp r(command, rows, num_rows \\ nil) do
    %Postgrex.Result{
      command: command,
      columns: nil,
      rows: rows,
      num_rows: num_rows || length(rows)
    }
  end

  describe "build_single/2 array_mode=true" do
    test "encodes a simple SELECT" do
      assert %{
               "command" => "SELECT",
               "rowCount" => 1,
               "fields" => [
                 %{"name" => "n", "dataTypeID" => 23, "format" => "text"}
               ],
               "rows" => [["42"]]
             } =
               @subject.build_single(
                 {q(["n"], [23]), r(:select, [[42]], 1)},
                 %{array_mode: true}
               )
    end

    test "preserves NULL as JSON null" do
      assert %{"rows" => [[nil]]} =
               @subject.build_single(
                 {q(["c"], [25]), r(:select, [[nil]], 1)},
                 %{array_mode: true}
               )
    end

    test "uppercases command verb" do
      assert %{"command" => "INSERT"} =
               @subject.build_single(
                 {q([], []), r(:insert, [], 0)},
                 %{array_mode: true}
               )

      assert %{"command" => "UPDATE"} =
               @subject.build_single(
                 {q([], []), r(:update, [], 0)},
                 %{array_mode: true}
               )
    end

    test "command nil → UNKNOWN" do
      assert %{"command" => "UNKNOWN"} =
               @subject.build_single({q([], []), r(nil, [])}, %{array_mode: true})
    end

    test "rowCount=0 for an empty SELECT" do
      assert %{"rowCount" => 0, "rows" => []} =
               @subject.build_single({q(["n"], [23]), r(:select, [], 0)}, %{array_mode: true})
    end

    test "multi-column row" do
      assert %{
               "fields" => [
                 %{"name" => "n", "dataTypeID" => 23},
                 %{"name" => "s", "dataTypeID" => 25}
               ],
               "rows" => [["1", "hi"]]
             } =
               @subject.build_single(
                 {q(["n", "s"], [23, 25]), r(:select, [[1, "hi"]], 1)},
                 %{array_mode: true}
               )
    end
  end

  describe "build_single/2 array_mode=false (default)" do
    test "rows become objects keyed by column name" do
      assert %{"rows" => [%{"n" => "1", "s" => "hi"}]} =
               @subject.build_single(
                 {q(["n", "s"], [23, 25]), r(:select, [[1, "hi"]], 1)}
               )
    end

    test "default array_mode is false" do
      out = @subject.build_single({q(["n"], [23]), r(:select, [[1]], 1)})
      assert [%{"n" => "1"}] = out["rows"]
    end

    test "NULL preserved in object form" do
      assert %{"rows" => [%{"c" => nil}]} =
               @subject.build_single({q(["c"], [25]), r(:select, [[nil]], 1)})
    end
  end

  describe "field metadata" do
    test "every field carries Neon-shape keys" do
      [field] = @subject.build_single({q(["x"], [23]), r(:select, [], 0)})["fields"]
      assert field["name"] == "x"
      assert field["dataTypeID"] == 23
      assert field["dataTypeSize"] == -1
      assert field["dataTypeModifier"] == -1
      assert field["format"] == "text"
    end

    test "missing OID falls back to 0" do
      [field] = @subject.build_single({q(["x"], []), r(:select, [], 0)})["fields"]
      assert field["dataTypeID"] == 0
    end
  end

  describe "build_batch/2" do
    test "wraps multiple results under 'results' key" do
      r1 = {q(["a"], [23]), r(:select, [[1]], 1)}
      r2 = {q(["b"], [25]), r(:select, [["x"]], 1)}

      assert %{"results" => [first, second]} =
               @subject.build_batch([r1, r2], %{array_mode: true})

      assert first["rows"] == [["1"]]
      assert second["rows"] == [["x"]]
    end

    test "empty batch" do
      assert %{"results" => []} = @subject.build_batch([])
    end
  end
end
