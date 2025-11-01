defmodule Supavisor.Protocol.StartupOptionsTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Supavisor.Protocol.StartupOptions

  doctest StartupOptions

  test "parses -c and -- tokens into a map" do
    options = StartupOptions.parse("-c search_path=schemaA,schemaB --log_level=info")

    assert options == %{"search_path" => "schemaA,schemaB", "log_level" => "info"}
  end

  test "-c flag supports immediate key without separator" do
    assert StartupOptions.parse("-csearch_path=public") == %{"search_path" => "public"}
  end

  test "does not swallow following options into search_path value" do
    assert StartupOptions.parse(
             "--search_path=schemaA -clog_level=info -c application_name=-test-"
           ) ==
             %{
               "search_path" => "schemaA",
               "log_level" => "info",
               "application_name" => "-test-"
             }
  end

  test "logs warning when -c argument lacks key/value" do
    log =
      capture_log(fn ->
        assert StartupOptions.parse("-c search_path") == %{}
      end)

    assert log =~ "StartupOptions: invalid argument \"search_path\""
  end

  test "keeps only valid options" do
    log =
      capture_log(fn ->
        assert StartupOptions.parse("--search_path=public -malformed") == %{
                 "search_path" => "public"
               }
      end)

    assert log =~ "ignored token \"-malformed\""
  end

  test "supports value with whitespaces" do
    pgoptions = ~s(--search_path=new\\ schema)
    expected = ~s(new\\ schema)

    assert StartupOptions.parse(pgoptions) == %{"search_path" => expected}
  end

  test "supports repeated whitespace separators" do
    options =
      StartupOptions.parse("-c search_path=schemaA  --log_level=debug\t\t-c application_name=app")

    assert options == %{
             "search_path" => "schemaA",
             "log_level" => "debug",
             "application_name" => "app"
           }
  end

  test "keeps escaped spaces inside double-quoted values" do
    pgoptions = ~s(--search_path="schema\\ with\\ space")
    expected = ~s("schema\\ with\\ space")

    assert StartupOptions.parse(pgoptions) == %{"search_path" => expected}
  end

  test "-c flag keeps escaped spaces inside quoted values" do
    pgoptions = ~s(-c search_path="schema\\ with\\ space")
    expected = ~s("schema\\ with\\ space")

    assert StartupOptions.parse(pgoptions) == %{"search_path" => expected}
  end

  test "skips invalid --key with empty value" do
    assert StartupOptions.parse("--mallformed=") == %{}
  end

  test "returns empty map for blank input" do
    assert StartupOptions.parse("   ") == %{}
  end

  test "ignores unsupported flags" do
    assert StartupOptions.parse("-search_path=public") == %{}
  end

  test "ignores stray escape token" do
    assert StartupOptions.parse("\\") == %{}
  end

  test "treats non-binary input as empty options" do
    assert StartupOptions.parse(nil) == %{}
  end
end
