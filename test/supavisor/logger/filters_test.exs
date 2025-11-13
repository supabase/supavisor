defmodule Supavisor.Logger.FiltersTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  @subject Supavisor.Logger.Filters

  doctest @subject

  describe "filter_auth_error" do
    test "log events without auth_error metadata are ignored" do
      log_event = %{
        msg: {:string, "foo bar"},
        level: :info,
        meta: %{}
      }

      assert :ignore == @subject.filter_auth_error(log_event, nil)
    end

    test "log events with auth_error: true are accepted" do
      log_event = %{
        msg: {:string, "foo bar"},
        level: :info,
        meta: %{
          auth_error: true
        }
      }

      assert log_event == @subject.filter_auth_error(log_event, nil)
    end
  end
end
