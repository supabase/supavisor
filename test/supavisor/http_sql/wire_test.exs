defmodule Supavisor.HttpSql.WireTest do
  use ExUnit.Case, async: true

  alias Supavisor.HttpSql.Wire

  defp bin(iodata), do: IO.iodata_to_binary(iodata)

  describe "parse/2" do
    test "unnamed statement, simple SQL" do
      <<?P, len::32, rest::binary>> = bin(Wire.parse("", "SELECT 1"))
      # 4 (len) + 1 (name NUL) + 8 (sql) + 1 (sql NUL) + 2 (param count) = 16
      assert len == 16
      assert rest == <<0, "SELECT 1", 0, 0::16>>
    end

    test "named statement" do
      packet = bin(Wire.parse("stmt1", "SELECT $1::int"))
      assert <<?P, _len::32, "stmt1", 0, "SELECT $1::int", 0, 0::16>> = packet
    end
  end

  describe "bind/3" do
    test "no parameters: format code count is 0, parameter count is 0" do
      <<?B, _len::32, rest::binary>> = bin(Wire.bind("", "", []))
      # portal NUL, stmt NUL, fmt count 0, param count 0, result fmt count 0
      assert rest == <<0, 0, 0::16, 0::16, 0::16>>
    end

    test "single text parameter" do
      <<?B, _len::32, rest::binary>> = bin(Wire.bind("", "", ["hello"]))

      assert <<
               0,
               0,
               # parameter format code count = 0 -> all params are text
               0::16,
               # parameter count
               1::16,
               # length
               5::32-signed,
               "hello",
               # result format code count
               0::16
             >> = rest
    end

    test "NULL parameter is length -1 with no value" do
      <<?B, _len::32, rest::binary>> = bin(Wire.bind("", "", [nil]))
      assert <<0, 0, 0::16, 1::16, -1::32-signed, 0::16>> = rest
    end

    test "mixed parameters: text, NULL, text" do
      <<?B, _len::32, rest::binary>> = bin(Wire.bind("", "", ["42", nil, "true"]))

      assert <<
               0,
               0,
               0::16,
               3::16,
               2::32-signed,
               "42",
               -1::32-signed,
               4::32-signed,
               "true",
               0::16
             >> = rest
    end

    test "non-empty portal and statement names" do
      <<?B, _len::32, rest::binary>> = bin(Wire.bind("portal_1", "stmt_1", []))
      assert <<"portal_1", 0, "stmt_1", 0, _::binary>> = rest
    end
  end

  describe "describe/2" do
    test "statement variant uses byte 'S'" do
      <<?D, len::32, rest::binary>> = bin(Wire.describe(:statement, ""))
      # 4 (len) + 1 ('S') + 1 (name NUL) = 6
      assert len == 6
      assert rest == <<?S, 0>>
    end

    test "portal variant uses byte 'P'" do
      <<?D, _len::32, rest::binary>> = bin(Wire.describe(:portal, "portal_x"))
      assert rest == <<?P, "portal_x", 0>>
    end
  end

  describe "execute/2" do
    test "default row limit is 0 (all rows)" do
      <<?E, len::32, rest::binary>> = bin(Wire.execute(""))
      # 4 + 1 (portal NUL) + 4 (row limit) = 9
      assert len == 9
      assert rest == <<0, 0::32>>
    end

    test "explicit row limit" do
      <<?E, _len::32, rest::binary>> = bin(Wire.execute("", 100))
      assert rest == <<0, 100::32>>
    end
  end

  describe "sync/0" do
    test "no payload, length field is 4" do
      assert bin(Wire.sync()) == <<?S, 4::32>>
    end
  end

  describe "close/2" do
    test "statement variant" do
      assert <<?C, _len::32, ?S, "stmt", 0>> = bin(Wire.close(:statement, "stmt"))
    end

    test "portal variant with empty name" do
      assert <<?C, len::32, ?P, 0>> = bin(Wire.close(:portal, ""))
      assert len == 6
    end
  end

  describe "query/1" do
    test "SET TRANSACTION" do
      sql = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
      <<?Q, len::32, rest::binary>> = bin(Wire.query(sql))
      assert len == byte_size(sql) + 5
      assert rest == sql <> <<0>>
    end
  end

  describe "length encoding" do
    test "length field includes itself but not the message-type byte" do
      <<?P, len::32, rest::binary>> = bin(Wire.parse("", "x"))
      # rest should be exactly (len - 4) bytes long
      assert byte_size(rest) == len - 4
    end

    test "length is big-endian 32-bit unsigned" do
      packet = bin(Wire.parse("", String.duplicate("x", 256)))
      <<?P, len::big-unsigned-32, _rest::binary>> = packet
      # 4 (len) + 1 (name NUL) + 256 (sql) + 1 (sql NUL) + 2 (param count) = 264
      assert len == 264
    end
  end
end
