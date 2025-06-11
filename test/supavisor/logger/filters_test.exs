defmodule Supavisor.Logger.FiltersTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  @subject Supavisor.Logger.Filters

  doctest @subject

  describe "filter_client_handler" do
    test "regular log events are ignored" do
      log_event = %{
        msg: {:string, "foo bar"},
        level: :info,
        meta: %{}
      }

      assert :ignore == @subject.filter_client_handler(log_event, :any)
    end

    test "log events with incorrect state are ignored" do
      log_event = %{
        msg: {:string, "foo bar"},
        level: :info,
        meta: %{
          mfa: {Supavisor.ClientHandler, :foo, 1},
          state: :another
        }
      }

      assert :ignore == @subject.filter_client_handler(log_event, :other)
    end

    test "log events with correct state are accepted" do
      log_event = %{
        msg: {:string, "foo bar"},
        level: :info,
        meta: %{
          mfa: {Supavisor.ClientHandler, :foo, 1},
          state: :some
        }
      }

      assert log_event == @subject.filter_client_handler(log_event, :some)
    end
  end
end
