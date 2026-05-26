defmodule Supavisor.HttpSql.ResponseBuilderTest do
  use ExUnit.Case, async: true

  @subject Supavisor.HttpSql.ResponseBuilder

  # Wire-shape input mirrors what `Supavisor.HttpSql.WireDecoder` produces.
  defp wire(cols, rows, command, num_rows \\ nil) do
    %{
      columns: Enum.map(cols, fn {name, oid} -> %{name: name, oid: oid} end),
      rows: rows,
      command: command,
      num_rows: num_rows || length(rows)
    }
  end

  describe "build_single/2 array_mode=true" do
    test "encodes a simple SELECT" do
      input = wire([{"n", 23}], [["42"]], "SELECT", 1)

      assert %{
               "command" => "SELECT",
               "rowCount" => 1,
               "fields" => [
                 %{"name" => "n", "dataTypeID" => 23, "format" => "text", "dataTypeSize" => -1}
               ],
               "rows" => [["42"]]
             } = @subject.build_single(input, %{array_mode: true})
    end

    test "preserves NULL as JSON null" do
      input = wire([{"c", 25}], [[nil]], "SELECT", 1)
      assert %{"rows" => [[nil]]} = @subject.build_single(input, %{array_mode: true})
    end

    test "uppercases command verb" do
      assert %{"command" => "INSERT"} =
               @subject.build_single(wire([], [], "INSERT", 0), %{array_mode: true})

      assert %{"command" => "UPDATE"} =
               @subject.build_single(wire([], [], "UPDATE", 0), %{array_mode: true})
    end

    test "command nil → UNKNOWN" do
      assert %{"command" => "UNKNOWN"} =
               @subject.build_single(wire([], [], nil, 0), %{array_mode: true})
    end

    test "rowCount=0 for an empty SELECT" do
      assert %{"rowCount" => 0, "rows" => []} =
               @subject.build_single(wire([{"n", 23}], [], "SELECT", 0), %{array_mode: true})
    end

    test "multi-column row" do
      input = wire([{"n", 23}, {"s", 25}], [["1", "hi"]], "SELECT", 1)

      assert %{
               "fields" => [
                 %{"name" => "n", "dataTypeID" => 23},
                 %{"name" => "s", "dataTypeID" => 25}
               ],
               "rows" => [["1", "hi"]]
             } = @subject.build_single(input, %{array_mode: true})
    end
  end

  describe "build_single/2 array_mode=false (default)" do
    test "rows become objects keyed by column name" do
      input = wire([{"n", 23}, {"s", 25}], [["1", "hi"]], "SELECT", 1)
      assert %{"rows" => [%{"n" => "1", "s" => "hi"}]} = @subject.build_single(input)
    end

    test "default array_mode is false" do
      out = @subject.build_single(wire([{"n", 23}], [["1"]], "SELECT", 1))
      assert [%{"n" => "1"}] = out["rows"]
    end

    test "NULL preserved in object form" do
      input = wire([{"c", 25}], [[nil]], "SELECT", 1)
      assert %{"rows" => [%{"c" => nil}]} = @subject.build_single(input)
    end
  end

  describe "field metadata" do
    test "every field carries Neon-shape keys" do
      [field] = @subject.build_single(wire([{"x", 23}], [], "SELECT", 0))["fields"]
      assert field["name"] == "x"
      assert field["dataTypeID"] == 23
      assert field["dataTypeSize"] == -1
      assert field["dataTypeModifier"] == -1
      assert field["format"] == "text"
    end
  end

  describe "build_batch/2" do
    test "wraps multiple results under 'results' key" do
      r1 = wire([{"a", 23}], [["1"]], "SELECT", 1)
      r2 = wire([{"b", 25}], [["x"]], "SELECT", 1)

      assert %{"results" => [first, second]} =
               @subject.build_batch([r1, r2], %{array_mode: true})

      assert first["rows"] == [["1"]]
      assert second["rows"] == [["x"]]
    end

    test "empty batch" do
      assert %{"results" => []} = @subject.build_batch([])
    end
  end

  describe "non-row commands" do
    test "UPDATE n yields empty fields/rows" do
      input = %{columns: nil, rows: [], command: "UPDATE", num_rows: 7}

      assert %{
               "command" => "UPDATE",
               "rowCount" => 7,
               "fields" => [],
               "rows" => []
             } = @subject.build_single(input)
    end
  end
end
