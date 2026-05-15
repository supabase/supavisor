defmodule Supavisor.Integration.HttpSqlE2ETest do
  @moduledoc """
  End-to-end smoke tests for the HTTP /sql endpoint exercised via the
  Phoenix router (`POST /sql`) — i.e. routing pipeline + plug + parser +
  NeonAuth + controller + facade + value encoder + response builder all
  wired together. Equivalent to a real HTTP client hitting Supavisor,
  short of bootstrapping a Cowboy listener.

  For a true wire-level smoke test against the `@neondatabase/serverless`
  client, see `test/integration/js/neon_http_sql/index.js` and the manual
  invocation procedure documented there.

  Excluded from the default `mix test` suite via `@moduletag :integration`.
  Run with:

      mix test --include integration test/integration/http_sql_e2e_test.exs
  """
  use SupavisorWeb.ConnCase, async: false

  import Supavisor.TenantsFixtures

  @moduletag :integration

  @conn_str "postgres://postgres.dev_tenant:postgres@localhost:6543/supavisor_test"

  setup do
    _ = tenant_fixture()
    tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")
    {:ok, _} = Supavisor.Tenants.update_tenant(tenant, %{feature_flags: %{"http_sql" => true}})

    cfg = Application.get_env(:supavisor, :http_sql, [])
    Application.put_env(:supavisor, :http_sql, Keyword.put(cfg, :enabled, true))

    Supervisor.terminate_child(Supavisor.Supervisor, Supavisor.HttpSql.PoolRegistry)
    {:ok, _} = Supervisor.restart_child(Supavisor.Supervisor, Supavisor.HttpSql.PoolRegistry)

    on_exit(fn -> Application.put_env(:supavisor, :http_sql, cfg) end)
    :ok
  end

  defp post_sql(conn, body, headers \\ []) do
    conn =
      conn
      |> put_req_header("content-type", "application/json")
      |> put_req_header("neon-connection-string", @conn_str)

    conn = Enum.reduce(headers, conn, fn {h, v}, acc -> put_req_header(acc, h, v) end)
    post(conn, "/sql", body)
  end

  test "neon-driver-shaped SELECT scalar", %{conn: conn} do
    conn = post_sql(conn, %{"query" => "SELECT 1 AS one", "params" => []})
    assert conn.status == 200

    body = Jason.decode!(conn.resp_body)
    assert body["command"] == "SELECT"
    assert body["rowCount"] == 1

    assert [%{"name" => "one", "dataTypeID" => oid, "format" => "text"}] = body["fields"]
    # OID for int4 (23) or int8 (20) depending on PG version's integer literal width
    assert oid in [23, 20, 21]
  end

  test "neon-driver-shaped SELECT with parameter", %{conn: conn} do
    conn = post_sql(conn, %{"query" => "SELECT $1::int + 1 AS n", "params" => [41]})
    assert conn.status == 200

    body = Jason.decode!(conn.resp_body)
    assert body["rowCount"] == 1
    # default array_mode=false → row object keyed by column name
    assert [%{"n" => "42"}] = body["rows"]
  end

  test "neon-driver-shaped NULL", %{conn: conn} do
    conn =
      post_sql(
        conn,
        %{"query" => "SELECT NULL::int AS n", "params" => []},
        [{"neon-array-mode", "true"}]
      )

    assert conn.status == 200
    assert %{"rows" => [[nil]]} = Jason.decode!(conn.resp_body)
  end

  test "neon-driver-shaped boolean", %{conn: conn} do
    conn = post_sql(conn, %{"query" => "SELECT true AS b", "params" => []})
    assert conn.status == 200
    # bool → "t"
    assert %{"rows" => [%{"b" => "t"}]} = Jason.decode!(conn.resp_body)
  end

  test "neon-driver-shaped date", %{conn: conn} do
    conn = post_sql(conn, %{"query" => "SELECT '2026-05-15'::date AS d", "params" => []})
    assert conn.status == 200
    assert %{"rows" => [%{"d" => "2026-05-15"}]} = Jason.decode!(conn.resp_body)
  end

  test "Postgres error code propagates to client", %{conn: conn} do
    conn = post_sql(conn, %{"query" => "SELECT FORM 1", "params" => []})
    assert conn.status == 400

    body = Jason.decode!(conn.resp_body)
    assert body["code"] == "42601"
    # Neon-shape: detail/hint/position/file may or may not be present
    assert is_binary(body["message"])
  end

  test "transaction batch with SET TRANSACTION READ ONLY", %{conn: conn} do
    conn =
      post_sql(
        conn,
        %{
          "queries" => [
            %{
              "query" => "SELECT current_setting('transaction_read_only') AS ro",
              "params" => []
            }
          ]
        },
        [{"neon-batch-read-only", "true"}]
      )

    assert conn.status == 200
    assert %{"results" => [%{"rows" => [%{"ro" => "on"}]}]} = Jason.decode!(conn.resp_body)
  end

  test "aggregate count returns a scalar text", %{conn: conn} do
    conn =
      post_sql(
        conn,
        %{
          "query" => "SELECT count(*)::int AS c FROM generate_series(1, 3)",
          "params" => []
        }
      )

    assert conn.status == 200
    assert %{"rows" => [%{"c" => "3"}]} = Jason.decode!(conn.resp_body)
  end
end
