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
  end
end
