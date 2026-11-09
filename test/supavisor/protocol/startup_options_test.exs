defmodule Supavisor.Protocol.StartupOptionsTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.StartupOptions

  doctest StartupOptions

  describe "encode/1" do
    test "empty map returns empty string" do
      assert StartupOptions.encode(%{}) == ""
    end

    test "single option without special characters" do
      assert StartupOptions.encode(%{"search_path" => "public"}) == "--search_path=public"
    end

    test "escapes spaces in values" do
      assert StartupOptions.encode(%{"search_path" => "schemaA, schemaB"}) ==
               "--search_path=schemaA,\\ schemaB"
    end

    test "escapes backslashes in values" do
      assert StartupOptions.encode(%{"search_path" => "a\\b"}) == "--search_path=a\\\\b"
    end

    test "escapes tabs in values" do
      assert StartupOptions.encode(%{"search_path" => "a\tb"}) == "--search_path=a\\\tb"
    end
  end

  describe "parse/1 roundtrips with encode/1" do
    test "simple value" do
      opts = %{"search_path" => "public"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with spaces" do
      opts = %{"search_path" => "schemaA, schemaB"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with backslash" do
      opts = %{"search_path" => "a\\b"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "multiple options" do
      opts = %{"search_path" => "public", "work_mem" => "64MB"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with tab" do
      opts = %{"search_path" => "a\tb"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with newline" do
      opts = %{"search_path" => "a\nb"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with carriage return" do
      opts = %{"search_path" => "a\rb"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with vertical tab" do
      opts = %{"search_path" => "a\vb"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with form feed" do
      opts = %{"search_path" => "a\fb"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end

    test "value with mixed whitespace" do
      opts = %{"search_path" => "a \t\n\r\v\fb"}
      assert opts == opts |> StartupOptions.encode() |> StartupOptions.parse()
    end
  end

  describe "validate/1" do
    test "converts boolean spellings case-insensitively" do
      for v <- ~w(1 t tr tru true y ye yes on TRUE On) do
        assert {%{"jit" => true}, [], []} = StartupOptions.validate(%{"jit" => v}),
               "expected #{inspect(v)} to be true"
      end

      for v <- ~w(0 f fa fal fals false n no of off OFF) do
        assert {%{"jit" => false}, [], []} = StartupOptions.validate(%{"jit" => v}),
               "expected #{inspect(v)} to be false"
      end
    end

    test "reports invalid boolean values" do
      for v <- ~w(o maybe 10 2) ++ [""] do
        assert {%{}, [{"jit", ^v}], []} = StartupOptions.validate(%{"jit" => v}),
               "expected #{inspect(v)} to be invalid"
      end
    end

    test "converts enum values to atoms" do
      assert {%{"log_level" => :info}, [], []} =
               StartupOptions.validate(%{"log_level" => "INFO"})
    end

    test "reports invalid enum values" do
      assert {%{}, [{"log_level", "trace"}], []} =
               StartupOptions.validate(%{"log_level" => "trace"})
    end

    test "passes string values through unchanged" do
      assert {%{"search_path" => "public, foo"}, [], []} =
               StartupOptions.validate(%{"search_path" => "public, foo"})
    end

    test "returns unknown options by name, sorted" do
      assert {%{"search_path" => "public"}, [], ["default_transaction_read_only", "work_mem"]} =
               StartupOptions.validate(%{
                 "work_mem" => "64MB",
                 "search_path" => "public",
                 "default_transaction_read_only" => "on"
               })
    end

    test "never returns the options Supavisor reads itself as unknown" do
      opts = %{
        "search_path" => "public",
        "jit" => "on",
        "client_tls" => "off",
        "log_level" => "debug",
        "client_ip" => "10.0.0.1",
        "reference" => "dev_tenant"
      }

      assert {%{"client_ip" => "10.0.0.1", "reference" => "dev_tenant"}, [], []} =
               StartupOptions.validate(opts)
    end

    test "drops invalid options and keeps the rest" do
      assert {%{"search_path" => "public"}, [{"jit", "maybe"}], []} =
               StartupOptions.validate(%{"jit" => "maybe", "search_path" => "public"})
    end

    test "empty map" do
      assert {%{}, [], []} = StartupOptions.validate(%{})
    end
  end

  describe "invalid_option_notice/1" do
    test "returns the boolean notice" do
      assert %{
               "S" => "NOTICE",
               "V" => "NOTICE",
               "C" => "22023",
               "M" => ~s(parameter "jit" requires a Boolean value)
             } == StartupOptions.invalid_option_notice({"jit", "maybe"})
    end

    test "uses the option name in the message" do
      assert %{"M" => ~s(parameter "client_tls" requires a Boolean value)} =
               StartupOptions.invalid_option_notice({"client_tls", "yep"})
    end

    test "returns the enum notice with a hint" do
      assert %{
               "S" => "NOTICE",
               "V" => "NOTICE",
               "C" => "22023",
               "M" => ~s(invalid value for parameter "log_level": "trace"),
               "H" => "Available values: debug, info, notice, warning, error."
             } == StartupOptions.invalid_option_notice({"log_level", "trace"})
    end
  end

  describe "unknown_option_notice/1" do
    test "names a single option and says how to set a PostgreSQL parameter" do
      assert %{
               "S" => "NOTICE",
               "V" => "NOTICE",
               "C" => "00000",
               "M" =>
                 ~s(unknown parameter "default_transaction_read_only" in startup options was ignored),
               "H" => "To set a PostgreSQL parameter, use ALTER ROLE or ALTER DATABASE ... SET."
             } == StartupOptions.unknown_option_notice(["default_transaction_read_only"])
    end

    test "lists several options in one message" do
      assert %{
               "M" =>
                 ~s(unknown parameters "default_transaction_read_only", "statement_timeout" in startup options were ignored)
             } =
               StartupOptions.unknown_option_notice([
                 "default_transaction_read_only",
                 "statement_timeout"
               ])
    end
  end
end
