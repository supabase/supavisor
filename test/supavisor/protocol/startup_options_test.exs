defmodule Supavisor.Protocol.StartupOptionsTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.StartupOptions

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
        assert {:ok, %{"jit" => true}} = StartupOptions.validate(%{"jit" => v}),
               "expected #{inspect(v)} to be true"
      end

      for v <- ~w(0 f fa fal fals false n no of off OFF) do
        assert {:ok, %{"jit" => false}} = StartupOptions.validate(%{"jit" => v}),
               "expected #{inspect(v)} to be false"
      end
    end

    test "rejects invalid boolean values" do
      for v <- ~w(o maybe 10 2) ++ [""] do
        assert {:error, {"jit", ^v}} = StartupOptions.validate(%{"jit" => v}),
               "expected #{inspect(v)} to be invalid"
      end
    end

    test "converts enum values to atoms" do
      assert {:ok, %{"log_level" => :info}} =
               StartupOptions.validate(%{"log_level" => "INFO"})
    end

    test "rejects invalid enum values" do
      assert {:error, {"log_level", "trace"}} =
               StartupOptions.validate(%{"log_level" => "trace"})
    end

    test "passes string values through unchanged" do
      assert {:ok, %{"search_path" => "public, foo"}} =
               StartupOptions.validate(%{"search_path" => "public, foo"})
    end

    test "passes unknown options through unchanged" do
      assert {:ok, %{"work_mem" => "64MB"}} =
               StartupOptions.validate(%{"work_mem" => "64MB"})
    end

    test "fails when any option is invalid" do
      assert {:error, {"jit", "maybe"}} =
               StartupOptions.validate(%{"jit" => "maybe", "search_path" => "public"})
    end

    test "empty map" do
      assert {:ok, %{}} = StartupOptions.validate(%{})
    end
  end

  describe "invalid_option_message/1" do
    test "returns the boolean error message" do
      assert {~s(parameter "jit" requires a Boolean value), nil} =
               StartupOptions.invalid_option_message({"jit", "maybe"})
    end

    test "uses the option name in the message" do
      assert {~s(parameter "client_tls" requires a Boolean value), nil} =
               StartupOptions.invalid_option_message({"client_tls", "yep"})
    end

    test "returns the enum error message and hint" do
      assert {~s(invalid value for parameter "log_level": "trace"),
              "Available values: debug, info, notice, warning, error."} =
               StartupOptions.invalid_option_message({"log_level", "trace"})
    end
  end
end
