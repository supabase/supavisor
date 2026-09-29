defmodule Supavisor.ClientAuthenticationTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Supavisor.Support.ClientAuthenticationHelpers

  alias Supavisor.ClientAuthentication

  describe "invalidate_global/4" do
    test "logs an error on RPC failure" do
      seed_cache("tenant", "user")

      assert capture_log(fn ->
               :ok =
                 ClientAuthentication.invalidate_global("some_id", "some_user", :infinity, [
                   node(),
                   :nonexistent
                 ])
             end) =~ ~r/Client authentication invalidation failure.*(nonexistent)/
    end
  end
end
