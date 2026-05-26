defmodule Supavisor.HttpSql.ClientHandlerTest do
  @moduledoc """
  Unit tests for `Supavisor.HttpSql.ClientHandler` callbacks. The end-to-end
  query path against a real Postgres lives in
  `test/integration/http_sql_v2_test.exs` (added later in the rewrite series).
  """

  use ExUnit.Case, async: true

  alias Supavisor.HttpSql.ClientHandler

  describe "db_status/2 (DbHandler callback)" do
    test "forwards :ready_for_query as a {:db_status, _} message to the target pid" do
      assert :ok = ClientHandler.db_status(self(), :ready_for_query)
      assert_received {:db_status, :ready_for_query}
    end

    test "forwards arbitrary status atoms (forwards-compat with future RFQ payloads)" do
      assert :ok = ClientHandler.db_status(self(), :something_else)
      assert_received {:db_status, :something_else}
    end
  end
end
