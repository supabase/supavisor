defmodule Supavisor.Integration.HttpSqlFacadeTest do
  @moduledoc """
  Integration tests for `Supavisor.HttpSql.execute/4` and
  `execute_batch/4`. Runs against a live `dev_tenant` (seeded in
  `priv/repo/seeds_after_migration.exs`) by routing Postgrex through the
  local supavisor proxy at `127.0.0.1:proxy_port_transaction`.

  Excluded from the default `mix test` suite via `@moduletag :integration`.
  Run with `mix test --include integration test/integration/http_sql_facade_test.exs`.
  """
  use Supavisor.DataCase, async: false

  import Supavisor.TenantsFixtures

  @moduletag :integration

  alias Supavisor.HttpSql

  setup do
    _ = tenant_fixture()
    :ok
  end

  defp ctx do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    %{
      tenant_external_id: "dev_tenant",
      user: db_conf[:username] <> ".dev_tenant",
      db_user: db_conf[:username],
      password: db_conf[:password],
      database: db_conf[:database] || "supavisor_test"
    }
  end

  describe "execute/4" do
    test "SELECT with literal value returns Neon-shaped response" do
      assert {:ok, body} = HttpSql.execute(ctx(), "SELECT 1 AS n", [])
      assert body["command"] == "SELECT"
      assert body["rowCount"] == 1
      assert [%{"name" => "n", "dataTypeID" => oid}] = body["fields"]
      assert oid in [23, 20]
      assert [_row] = body["rows"]
    end

    test "SELECT with parameter returns rendered text" do
      assert {:ok, body} = HttpSql.execute(ctx(), "SELECT $1::int + 1 AS n", [41])
      assert body["rowCount"] == 1

      case body["rows"] do
        [%{"n" => v}] -> assert v == "42"
        [[v]] -> assert v == "42"
      end
    end

    test "array_mode=true returns row arrays" do
      assert {:ok, body} =
               HttpSql.execute(ctx(), "SELECT 1::int AS n", [], %{array_mode: true})

      assert [["1"]] = body["rows"]
    end

    test "array_mode=false (default) returns row objects" do
      assert {:ok, body} = HttpSql.execute(ctx(), "SELECT 'hi' AS s", [])
      assert [%{"s" => "hi"}] = body["rows"]
    end

    test "NULL becomes JSON null" do
      assert {:ok, body} =
               HttpSql.execute(ctx(), "SELECT NULL::int AS n", [], %{array_mode: true})

      assert [[nil]] = body["rows"]
    end

    test "syntax error returns %PgError{}" do
      assert {:error, %Supavisor.HttpSql.PgError{code: "42601"}} =
               HttpSql.execute(ctx(), "SELECT FORM 1", [])
    end
  end

  describe "execute_batch/4" do
    test "runs multiple queries in one transaction" do
      assert {:ok, body} =
               HttpSql.execute_batch(
                 ctx(),
                 [
                   %{sql: "SELECT 1 AS a", params: []},
                   %{sql: "SELECT 2 AS a", params: []}
                 ],
                 %{},
                 %{array_mode: true}
               )

      assert %{"results" => [r1, r2]} = body
      assert r1["rows"] == [["1"]]
      assert r2["rows"] == [["2"]]
    end

    test "respects Neon-Batch-Read-Only header" do
      assert {:ok, body} =
               HttpSql.execute_batch(
                 ctx(),
                 [
                   %{sql: "SELECT current_setting('transaction_read_only') AS ro", params: []}
                 ],
                 %{read_only: "true"},
                 %{array_mode: true}
               )

      assert %{"results" => [%{"rows" => [["on"]]}]} = body
    end

    test "rolls back on error inside the batch" do
      assert {:error, %Supavisor.HttpSql.PgError{code: code}} =
               HttpSql.execute_batch(
                 ctx(),
                 [
                   %{sql: "SELECT 1", params: []},
                   %{sql: "SELECT FORM 1", params: []}
                 ],
                 %{},
                 %{}
               )

      assert code in ["42601", "42703"]
    end

    test "invalid isolation header returns error before opening tx" do
      assert {:error, {:invalid_isolation, "Chaotic"}} =
               HttpSql.execute_batch(
                 ctx(),
                 [%{sql: "SELECT 1", params: []}],
                 %{isolation: "Chaotic"},
                 %{}
               )
    end
  end

  describe "row cap enforcement" do
    setup do
      cfg = Application.get_env(:supavisor, :http_sql, [])
      Application.put_env(:supavisor, :http_sql, Keyword.put(cfg, :max_response_rows, 5))
      on_exit(fn -> Application.put_env(:supavisor, :http_sql, cfg) end)
      :ok
    end

    test "exceeding max_response_rows returns {:row_limit_exceeded, cap}" do
      assert {:error, {:row_limit_exceeded, 5}} =
               HttpSql.execute(
                 ctx(),
                 "SELECT i FROM generate_series(1, 100) AS s(i)",
                 [],
                 %{}
               )
    end

    test "under-cap query succeeds" do
      assert {:ok, %{"rowCount" => 3}} =
               HttpSql.execute(
                 ctx(),
                 "SELECT i FROM generate_series(1, 3) AS s(i)",
                 [],
                 %{}
               )
    end
  end
end
