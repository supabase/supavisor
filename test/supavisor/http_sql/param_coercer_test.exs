defmodule Supavisor.HttpSql.ParamCoercerTest do
  use ExUnit.Case, async: true

  @subject Supavisor.HttpSql.ParamCoercer

  describe "coerce/2 — nil" do
    test "nil for any OID is nil" do
      for oid <- [16, 17, 20, 21, 23, 25, 700, 701, 1700, 1082, 1184, 2950, 3802, 99_999] do
        assert @subject.coerce(nil, oid) == nil
      end
    end
  end

  describe "coerce/2 — bool (16)" do
    test "truthy spellings → true" do
      for v <- ["t", "T", "true", "TRUE", "True", "1"] do
        assert @subject.coerce(v, 16) == true
      end
    end

    test "falsy spellings → false" do
      for v <- ["f", "F", "false", "FALSE", "False", "0"] do
        assert @subject.coerce(v, 16) == false
      end
    end

    test "invalid bool raises" do
      assert_raise ArgumentError, fn -> @subject.coerce("maybe", 16) end
    end

    test "passthrough for already-native bool" do
      assert @subject.coerce(true, 16) == true
      assert @subject.coerce(false, 16) == false
    end
  end

  describe "coerce/2 — integers (int2 / int4 / int8)" do
    test "positive int4" do
      assert @subject.coerce("42", 23) == 42
    end

    test "negative int4" do
      assert @subject.coerce("-7", 23) == -7
    end

    test "int2" do
      assert @subject.coerce("32767", 21) == 32_767
    end

    test "int8 — max value" do
      assert @subject.coerce("9223372036854775807", 20) == 9_223_372_036_854_775_807
    end

    test "int8 — min value" do
      assert @subject.coerce("-9223372036854775808", 20) == -9_223_372_036_854_775_808
    end

    test "non-numeric string raises" do
      assert_raise ArgumentError, fn -> @subject.coerce("not-a-number", 23) end
    end

    test "passthrough for already-native int" do
      assert @subject.coerce(42, 23) == 42
    end
  end

  describe "coerce/2 — floats (float4 / float8)" do
    test "decimal" do
      assert @subject.coerce("3.14", 701) == 3.14
    end

    test "scientific notation" do
      assert @subject.coerce("1.5e3", 701) == 1500.0
    end

    test "NaN special" do
      assert @subject.coerce("NaN", 701) == :nan
    end

    test "Infinity special" do
      assert @subject.coerce("Infinity", 701) == :infinity
    end

    test "-Infinity special" do
      assert @subject.coerce("-Infinity", 701) == :negative_infinity
    end

    test "float4 same encoding rules" do
      assert @subject.coerce("0.5", 700) == 0.5
    end

    test "passthrough for native float" do
      assert @subject.coerce(2.5, 701) == 2.5
    end
  end

  describe "coerce/2 — numeric (1700)" do
    test "string → Decimal preserves precision" do
      result = @subject.coerce("123456789012345.6789", 1700)
      assert %Decimal{} = result
      assert Decimal.equal?(result, Decimal.new("123456789012345.6789"))
    end

    test "integer-valued string" do
      result = @subject.coerce("42", 1700)
      assert Decimal.equal?(result, Decimal.new("42"))
    end

    test "negative" do
      result = @subject.coerce("-99.99", 1700)
      assert Decimal.equal?(result, Decimal.new("-99.99"))
    end
  end

  describe "coerce/2 — bytea (17)" do
    test "\\\\x-prefixed hex" do
      assert @subject.coerce("\\xdeadbeef", 17) == <<0xDE, 0xAD, 0xBE, 0xEF>>
    end

    test "empty bytea" do
      assert @subject.coerce("\\x", 17) == <<>>
    end

    test "mixed-case hex tolerated" do
      assert @subject.coerce("\\xDeAdBeEf", 17) == <<0xDE, 0xAD, 0xBE, 0xEF>>
    end

    test "binary without \\\\x prefix passes through" do
      assert @subject.coerce(<<1, 2, 3>>, 17) == <<1, 2, 3>>
    end
  end

  describe "coerce/2 — text-like (25 / 1043 / 18 / 19)" do
    test "text identity" do
      assert @subject.coerce("hello", 25) == "hello"
    end

    test "varchar identity" do
      assert @subject.coerce("v", 1043) == "v"
    end

    test "name identity" do
      assert @subject.coerce("n", 19) == "n"
    end

    test "multibyte UTF-8" do
      assert @subject.coerce("привіт 🐘", 25) == "привіт 🐘"
    end
  end

  describe "coerce/2 — date (1082)" do
    test "ISO date" do
      assert @subject.coerce("2026-05-15", 1082) == ~D[2026-05-15]
    end

    test "invalid date raises" do
      assert_raise ArgumentError, fn -> @subject.coerce("not-a-date", 1082) end
    end
  end

  describe "coerce/2 — time (1083)" do
    test "ISO time" do
      assert @subject.coerce("14:30:00", 1083) == ~T[14:30:00]
    end

    test "with microseconds" do
      assert @subject.coerce("14:30:00.123456", 1083) ==
               Time.new!(14, 30, 0, {123_456, 6})
    end
  end

  describe "coerce/2 — timestamp (1114)" do
    test "ISO with T" do
      assert @subject.coerce("2026-05-15T14:30:00", 1114) == ~N[2026-05-15 14:30:00]
    end

    test "Postgres text format with space" do
      assert @subject.coerce("2026-05-15 14:30:00", 1114) == ~N[2026-05-15 14:30:00]
    end

    test "with microseconds" do
      assert @subject.coerce("2026-05-15 14:30:00.123456", 1114) ==
               NaiveDateTime.new!(2026, 5, 15, 14, 30, 0, {123_456, 6})
    end
  end

  describe "coerce/2 — timestamptz (1184)" do
    test "Postgres text with +00 suffix" do
      assert {:ok, dt, _} =
               DateTime.from_iso8601(
                 @subject.coerce("2026-05-15T14:30:00+00:00", 1184) |> DateTime.to_iso8601()
               )

      _ = dt
    end

    test "round-trip from libpq-style format" do
      # "2026-05-15 14:30:00+00" → DateTime
      coerced = @subject.coerce("2026-05-15 14:30:00+00:00", 1184)
      assert %DateTime{} = coerced
      assert DateTime.to_iso8601(coerced) =~ "2026-05-15T14:30:00"
    end

    test "non-UTC offset shifted into UTC (Postgrex stores timestamptz as UTC)" do
      coerced = @subject.coerce("2026-05-15 14:30:00+03:00", 1184)
      # +03:00 input → UTC representation is 11:30:00Z
      assert coerced.utc_offset == 0
      assert coerced.hour == 11
      assert coerced.minute == 30
    end
  end

  describe "coerce/2 — uuid (2950)" do
    test "36-char canonical form → 16-byte binary" do
      assert @subject.coerce("550e8400-e29b-41d4-a716-446655440000", 2950) ==
               <<0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55,
                 0x44, 0x00, 0x00>>
    end

    test "non-36-char passes through" do
      raw = <<1, 2, 3>>
      assert @subject.coerce(raw, 2950) == raw
    end
  end

  describe "coerce/2 — json / jsonb (114, 3802)" do
    test "object string → map" do
      assert @subject.coerce(~s({"a":1}), 3802) == %{"a" => 1}
    end

    test "array string → list" do
      assert @subject.coerce("[1,2,3]", 114) == [1, 2, 3]
    end

    test "scalar string → scalar" do
      assert @subject.coerce(~s("hi"), 3802) == "hi"
      assert @subject.coerce("42", 114) == 42
      assert @subject.coerce("true", 114) == true
    end

    test "invalid JSON raises" do
      assert_raise Jason.DecodeError, fn -> @subject.coerce("{not json}", 3802) end
    end
  end

  describe "coerce/2 — interval (1186)" do
    test "simple unit text" do
      assert %Postgrex.Interval{months: 12} = @subject.coerce("1 year", 1186)
    end

    test "multi-unit text" do
      result = @subject.coerce("1 year 2 mons 3 days 4 hours", 1186)
      assert %Postgrex.Interval{months: 14, days: 3, secs: 14_400} = result
    end

    test "seconds" do
      assert %Postgrex.Interval{secs: 30} = @subject.coerce("30 sec", 1186)
    end

    test "negative components" do
      assert %Postgrex.Interval{months: -3} = @subject.coerce("-3 mons", 1186)
    end

    test "garbage text → zero interval (best-effort)" do
      assert %Postgrex.Interval{months: 0, days: 0, secs: 0} =
               @subject.coerce("garbage", 1186)
    end
  end

  describe "coerce/2 — array types" do
    test "int4 array" do
      assert [1, 2, 3] = @subject.coerce(["1", "2", "3"], 1007)
    end

    test "text array" do
      assert ["hi", "world"] = @subject.coerce(["hi", "world"], 1009)
    end

    test "bool array" do
      assert [true, false, true] = @subject.coerce(["t", "false", "1"], 1000)
    end

    test "array with NULLs preserves nil" do
      assert [1, nil, 3] = @subject.coerce(["1", nil, "3"], 1007)
    end

    test "float8 array" do
      assert [3.14, 2.5] = @subject.coerce(["3.14", "2.5"], 1022)
    end
  end

  describe "coerce/2 — unknown OIDs" do
    test "passes through binary" do
      assert @subject.coerce("anything", 99_999_991) == "anything"
    end

    test "passes through atom" do
      assert @subject.coerce(:foo, 99_999_992) == :foo
    end

    test "passes through integer" do
      assert @subject.coerce(42, 99_999_993) == 42
    end

    test "nil OID treated as unknown" do
      assert @subject.coerce("hi", nil) == "hi"
    end
  end

  describe "coerce_list/2" do
    test "matching lengths coerces by OID" do
      assert @subject.coerce_list(["1", "hi", "t"], [23, 25, 16]) == [1, "hi", true]
    end

    test "nil oids returns params unchanged" do
      assert @subject.coerce_list(["1", "hi"], nil) == ["1", "hi"]
    end

    test "mismatched lengths returns params unchanged" do
      assert @subject.coerce_list(["1", "2"], [23]) == ["1", "2"]
    end

    test "empty list" do
      assert @subject.coerce_list([], []) == []
    end

    test "NULL elements preserved" do
      assert @subject.coerce_list(["1", nil, "3"], [23, 23, 23]) == [1, nil, 3]
    end
  end
end
