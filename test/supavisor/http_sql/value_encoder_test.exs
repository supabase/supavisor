defmodule Supavisor.HttpSql.ValueEncoderTest do
  use ExUnit.Case, async: true

  @subject Supavisor.HttpSql.ValueEncoder

  describe "encode/2 — nil" do
    test "nil round-trips to nil for any OID" do
      for oid <- [16, 17, 23, 25, 1700, 1184, 114, 2950, 1007] do
        assert @subject.encode(nil, oid) == nil
      end
    end
  end

  describe "encode/2 — booleans" do
    test "true → t" do
      assert @subject.encode(true, 16) == "t"
    end

    test "false → f" do
      assert @subject.encode(false, 16) == "f"
    end
  end

  describe "encode/2 — integers" do
    test "int2 / int4 / int8 stringify" do
      assert @subject.encode(0, 21) == "0"
      assert @subject.encode(42, 23) == "42"
      assert @subject.encode(-9_223_372_036_854_775_808, 20) == "-9223372036854775808"
    end
  end

  describe "encode/2 — floats" do
    test "float8 stringifies" do
      assert @subject.encode(3.14, 701) == "3.14"
    end

    test "float4 stringifies" do
      assert @subject.encode(0.5, 700) == "0.5"
    end

    test "integer fed into float OID gets a .0 suffix" do
      assert @subject.encode(7, 701) == "7.0"
    end

    test "NaN" do
      assert @subject.encode(:nan, 701) == "NaN"
    end

    test "+Infinity" do
      assert @subject.encode(:infinity, 701) == "Infinity"
    end

    test "-Infinity" do
      assert @subject.encode(:negative_infinity, 701) == "-Infinity"
    end
  end

  describe "encode/2 — text family" do
    test "text identity" do
      assert @subject.encode("hello", 25) == "hello"
    end

    test "varchar identity" do
      assert @subject.encode("v", 1043) == "v"
    end

    test "bpchar identity" do
      assert @subject.encode("c", 1042) == "c"
    end

    test "name identity" do
      assert @subject.encode("n", 19) == "n"
    end

    test "UTF-8 multibyte" do
      assert @subject.encode("привіт 🐘", 25) == "привіт 🐘"
    end
  end

  describe "encode/2 — bytea" do
    test "hex-encoded with \\x prefix" do
      assert @subject.encode(<<0xDE, 0xAD, 0xBE, 0xEF>>, 17) == "\\xdeadbeef"
    end

    test "empty bytea" do
      assert @subject.encode(<<>>, 17) == "\\x"
    end

    test "high-bit bytes" do
      assert @subject.encode(<<0xFF, 0x00, 0x7F>>, 17) == "\\xff007f"
    end
  end

  describe "encode/2 — numeric" do
    test "Decimal renders without scientific notation" do
      assert @subject.encode(Decimal.new("99.99"), 1700) == "99.99"
    end

    test "large Decimal" do
      assert @subject.encode(Decimal.new("123456789012345.6789"), 1700) ==
               "123456789012345.6789"
    end

    test "integer fallback" do
      assert @subject.encode(42, 1700) == "42"
    end
  end

  describe "encode/2 — date/time" do
    test "date" do
      assert @subject.encode(~D[2026-05-15], 1082) == "2026-05-15"
    end

    test "time" do
      assert @subject.encode(~T[14:30:00], 1083) == "14:30:00"
    end

    test "timestamp (no zone)" do
      assert @subject.encode(~N[2026-05-15 14:30:00], 1114) == "2026-05-15 14:30:00"
    end

    test "timestamptz UTC" do
      assert @subject.encode(~U[2026-05-15 14:30:00Z], 1184) ==
               "2026-05-15 14:30:00+00"
    end

    test "timestamptz with microseconds" do
      dt = DateTime.from_naive!(~N[2026-05-15 14:30:00.123456], "Etc/UTC")
      assert @subject.encode(dt, 1184) == "2026-05-15 14:30:00.123456+00"
    end
  end

  describe "encode/2 — uuid" do
    test "16-byte binary → canonical hex" do
      bin = <<0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4,
              0xA7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00>>

      assert @subject.encode(bin, 2950) == "550e8400-e29b-41d4-a716-446655440000"
    end

    test "already-formatted string passes through" do
      assert @subject.encode("550e8400-e29b-41d4-a716-446655440000", 2950) ==
               "550e8400-e29b-41d4-a716-446655440000"
    end
  end

  describe "encode/2 — json / jsonb" do
    test "map → JSON object string" do
      assert @subject.encode(%{"a" => 1}, 3802) == ~s({"a":1})
    end

    test "list → JSON array string" do
      assert @subject.encode([1, 2, 3], 114) == "[1,2,3]"
    end

    test "scalar → JSON string" do
      assert @subject.encode("hi", 3802) == ~s("hi")
    end
  end

  describe "encode/2 — arrays" do
    test "int4 array" do
      assert @subject.encode([1, 2, 3], 1007) == "{1,2,3}"
    end

    test "int4 array with NULL" do
      assert @subject.encode([1, nil, 3], 1007) == "{1,NULL,3}"
    end

    test "text array, plain elements" do
      assert @subject.encode(["a", "b"], 1009) == "{a,b}"
    end

    test "text array, comma-containing element gets quoted" do
      assert @subject.encode(["a,b", "c"], 1009) == ~s({"a,b",c})
    end

    test "text array, brace-containing element gets quoted" do
      assert @subject.encode(["a{b", "c"], 1009) == ~s({"a{b",c})
    end

    test "text array, double-quote-containing element gets quoted with escape" do
      assert @subject.encode([~s(a"b)], 1009) == ~s({"a\\"b"})
    end

    test "text array, backslash-containing element gets quoted with escape" do
      assert @subject.encode(["a\\b"], 1009) == ~s({"a\\\\b"})
    end

    test "empty text element gets quoted" do
      assert @subject.encode([""], 1009) == ~s({""})
    end

    test ~s(text element equal to literal "NULL" gets quoted) do
      assert @subject.encode(["NULL"], 1009) == ~s({"NULL"})
    end

    test "nested int4 array" do
      assert @subject.encode([[1, 2], [3, 4]], 1007) == "{{1,2},{3,4}}"
    end
  end

  describe "encode/2 — unknown OID fallback" do
    test "binary value falls through" do
      assert @subject.encode("anything", 99_999_991) == "anything"
    end

    test "atom value falls through" do
      assert @subject.encode(:foo, 99_999_992) == "foo"
    end

    test "integer value falls through" do
      assert @subject.encode(42, 99_999_993) == "42"
    end
  end

  describe "encode_row/2" do
    test "encodes a mixed-type row" do
      row = [1, "hi", true, nil]
      oids = [23, 25, 16, 23]
      assert @subject.encode_row(row, oids) == ["1", "hi", "t", nil]
    end
  end
end
