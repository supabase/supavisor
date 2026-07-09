defmodule Supavisor.HttpSql.PgErrorTest do
  use ExUnit.Case, async: true

  alias Supavisor.HttpSql.PgError

  describe "exception/1" do
    test "extracts code, severity, message from PG ErrorResponse fields" do
      err =
        PgError.exception(%{
          "S" => "ERROR",
          "V" => "ERROR",
          "C" => "42601",
          "M" => "syntax error at or near \"FROM\"",
          "P" => "8",
          "F" => "scan.l",
          "L" => "1158",
          "R" => "scanner_yyerror"
        })

      assert err.code == "42601"
      assert err.severity == "ERROR"
      assert err.message =~ "syntax error"
      assert err.fields["P"] == "8"
      assert err.fields["F"] == "scan.l"
    end

    test "falls back to V when S is missing" do
      err = PgError.exception(%{"V" => "FATAL", "C" => "57P01", "M" => "shutdown"})
      assert err.severity == "FATAL"
    end

    test "nil fields are kept consistent" do
      err = PgError.exception(%{})
      assert err.code == nil
      assert err.severity == nil
      assert err.message == nil
      assert err.fields == %{}
    end
  end

  describe "message/1 (Exception protocol)" do
    test "formats as (CODE) MESSAGE when both present" do
      err = PgError.exception(%{"C" => "42601", "M" => "syntax error"})
      assert Exception.message(err) == "(42601) syntax error"
    end

    test "uses message alone when code is missing" do
      err = PgError.exception(%{"M" => "something broke"})
      assert Exception.message(err) == "something broke"
    end

    test "falls back to a generic string when message is missing" do
      err = PgError.exception(%{"C" => "XX000"})
      assert Exception.message(err) == "unknown postgres error"
    end
  end
end
