defmodule Supavisor.Logger.FiltersTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  @subject Supavisor.Logger.Filters

  doctest @subject

  describe "filter_auth_error" do
    test "log events without auth_log metadata are ignored" do
      log_event = %{
        msg: {:string, "foo bar"},
        level: :info,
        meta: %{}
      }

      assert :ignore == @subject.filter_auth_error(log_event, nil)
    end

    test "log events with auth_log: true are accepted" do
      log_event = %{
        msg: {:string, "foo bar"},
        level: :info,
        meta: %{
          auth_log: true
        }
      }

      assert log_event == @subject.filter_auth_error(log_event, nil)
    end
  end
end
