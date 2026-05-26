defmodule Supavisor.HttpSql.ParamsTest do
  use ExUnit.Case, async: true

  alias Supavisor.HttpSql.Params

  describe "stringify/1 — primitives" do
    test "nil maps to nil (SQL NULL sentinel for Wire.bind/3)" do
      assert Params.stringify(nil) == nil
    end

    test "binary passes through untouched" do
      assert Params.stringify("hello") == "hello"
      assert Params.stringify("") == ""
      assert Params.stringify("multi\nline") == "multi\nline"
    end

    test "booleans use PostgreSQL's `t`/`f` short form" do
      assert Params.stringify(true) == "t"
      assert Params.stringify(false) == "f"
    end

    test "integers (incl. negative and large)" do
      assert Params.stringify(0) == "0"
      assert Params.stringify(42) == "42"
      assert Params.stringify(-7) == "-7"
      assert Params.stringify(9_223_372_036_854_775_807) == "9223372036854775807"
    end

    test "floats" do
      assert Params.stringify(1.5) == "1.5"
      assert Params.stringify(-0.001) == "-0.001"
    end

    test "float specials by atom name" do
      assert Params.stringify(:nan) == "NaN"
      assert Params.stringify(:infinity) == "Infinity"
      assert Params.stringify(:negative_infinity) == "-Infinity"
    end

    test "other atoms stringify to their name" do
      assert Params.stringify(:ok) == "ok"
      assert Params.stringify(:hello_world) == "hello_world"
    end

    test "non-special-cased atoms (already covered above) round-trip" do
      assert Params.stringify(:foo) == "foo"
    end
  end

  describe "stringify/1 — composites are JSON-encoded" do
    test "list becomes a JSON array" do
      assert Params.stringify([1, 2, 3]) == "[1,2,3]"
      assert Params.stringify(["a", "b"]) == "[\"a\",\"b\"]"
    end

    test "map becomes a JSON object" do
      assert Params.stringify(%{"k" => "v"}) == "{\"k\":\"v\"}"
    end

    test "nested mixed structure" do
      assert Params.stringify(%{"items" => [1, 2]}) == "{\"items\":[1,2]}"
    end
  end

  describe "stringify_list/1" do
    test "empty list" do
      assert Params.stringify_list([]) == []
    end

    test "mixed types preserve order and per-element rules" do
      assert Params.stringify_list([1, nil, "hi", true, %{"a" => 1}]) ==
               ["1", nil, "hi", "t", "{\"a\":1}"]
    end

    test "all-nil list is preserved as all nils" do
      assert Params.stringify_list([nil, nil, nil]) == [nil, nil, nil]
    end
  end

  describe "stringify/1 — round-trip with Wire.bind/3" do
    # The whole point of these conversions is that they slot into Wire.bind/3
    # without re-encoding. Sanity-check by composing the two and decoding.
    test "stringify-then-bind produces well-formed parameter bytes" do
      params = [1, nil, "hi", true]
      stringified = Params.stringify_list(params)
      bind = Supavisor.HttpSql.Wire.bind("", "", stringified) |> IO.iodata_to_binary()

      assert <<?B, _len::32, 0, 0, 0::16, 4::16, rest::binary>> = bind

      # First param: text "1"
      assert <<1::32-signed, "1", more::binary>> = rest
      # Second param: NULL (-1)
      assert <<-1::32-signed, rest2::binary>> = more
      # Third param: text "hi"
      assert <<2::32-signed, "hi", more3::binary>> = rest2
      # Fourth param: text "t"
      assert <<1::32-signed, "t", _trailer::binary>> = more3
    end
  end
end
