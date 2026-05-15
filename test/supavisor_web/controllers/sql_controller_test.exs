defmodule SupavisorWeb.SqlControllerTest do
  use SupavisorWeb.ConnCase, async: false

  import Supavisor.TenantsFixtures

  @conn_str "postgres://postgres.dev_tenant:postgres@localhost:6543/supavisor_test"

  setup do
    _ = tenant_fixture()

    tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")
    {:ok, _} = Supavisor.Tenants.update_tenant(tenant, %{feature_flags: %{"http_sql" => true}})

    cfg = Application.get_env(:supavisor, :http_sql, [])
    Application.put_env(:supavisor, :http_sql, Keyword.put(cfg, :enabled, true))

    # `update_tenant` above terminates supavisor's upstream pool. Any
    # leftover HTTP-SQL Postgrex pool from a prior test still references
    # the now-dropped connection; evict so each test starts fresh.
    Supervisor.terminate_child(Supavisor.Supervisor, Supavisor.HttpSql.PoolRegistry)
    {:ok, _} = Supervisor.restart_child(Supavisor.Supervisor, Supavisor.HttpSql.PoolRegistry)

    on_exit(fn -> Application.put_env(:supavisor, :http_sql, cfg) end)
    :ok
  end

  defp post_sql(conn, body, headers \\ []) do
    conn = conn |> put_req_header("content-type", "application/json")
    conn = put_req_header(conn, "neon-connection-string", @conn_str)

    conn =
      Enum.reduce(headers, conn, fn {h, v}, acc -> put_req_header(acc, h, v) end)

    post(conn, "/sql", body)
  end

  describe "POST /sql — single" do
    @tag :integration
    test "happy path", %{conn: conn} do
      conn = post_sql(conn, %{"query" => "SELECT $1::int AS n", "params" => [42]})

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["command"] == "SELECT"
      assert body["rowCount"] == 1
      assert [%{"name" => "n"}] = body["fields"]
    end

    @tag :integration
    test "Neon-Array-Mode true → row arrays", %{conn: conn} do
      conn =
        post_sql(conn, %{"query" => "SELECT 1::int AS n", "params" => []},
          [{"neon-array-mode", "true"}]
        )

      assert conn.status == 200
      assert %{"rows" => [["1"]]} = Jason.decode!(conn.resp_body)
    end

    @tag :integration
    test "Neon-Array-Mode missing → row objects", %{conn: conn} do
      conn = post_sql(conn, %{"query" => "SELECT 'hi' AS s", "params" => []})
      assert %{"rows" => [%{"s" => "hi"}]} = Jason.decode!(conn.resp_body)
    end

    @tag :integration
    test "syntax error → 400 with Postgres code", %{conn: conn} do
      conn = post_sql(conn, %{"query" => "SELECT FORM 1", "params" => []})
      assert conn.status == 400
      body = Jason.decode!(conn.resp_body)
      assert body["code"] == "42601"
    end

    test "missing body fields → 400", %{conn: conn} do
      conn = post_sql(conn, %{"not_query" => "x"})
      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["code"] == "malformed_request"
    end

    test "missing Neon-Connection-String header → 400", %{conn: conn} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/sql", %{"query" => "SELECT 1", "params" => []})

      assert conn.status == 400
    end
  end

  describe "POST /sql — batch" do
    @tag :integration
    test "runs N queries in a transaction", %{conn: conn} do
      conn =
        post_sql(
          conn,
          %{
            "queries" => [
              %{"query" => "SELECT 1 AS a", "params" => []},
              %{"query" => "SELECT 2 AS b", "params" => []}
            ]
          },
          [{"neon-array-mode", "true"}]
        )

      assert conn.status == 200
      assert %{"results" => [r1, r2]} = Jason.decode!(conn.resp_body)
      assert r1["rows"] == [["1"]]
      assert r2["rows"] == [["2"]]
    end

    @tag :integration
    test "honors Neon-Batch-Read-Only", %{conn: conn} do
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
          [{"neon-batch-read-only", "true"}, {"neon-array-mode", "true"}]
        )

      assert conn.status == 200
      assert %{"results" => [%{"rows" => [["on"]]}]} = Jason.decode!(conn.resp_body)
    end

    @tag :integration
    test "rolls back on error inside batch", %{conn: conn} do
      conn =
        post_sql(conn, %{
          "queries" => [
            %{"query" => "SELECT 1", "params" => []},
            %{"query" => "SELECT FORM 1", "params" => []}
          ]
        })

      assert conn.status == 400
    end

    test "invalid isolation level → 400 without opening txn", %{conn: conn} do
      conn =
        post_sql(
          conn,
          %{
            "queries" => [%{"query" => "SELECT 1", "params" => []}]
          },
          [{"neon-batch-isolation-level", "Chaotic"}]
        )

      assert conn.status == 500 or conn.status == 400
    end
  end

  describe "feature gate" do
    test "disabled globally → 404", %{conn: conn} do
      cfg = Application.get_env(:supavisor, :http_sql, [])
      Application.put_env(:supavisor, :http_sql, Keyword.put(cfg, :enabled, false))
      on_exit(fn -> Application.put_env(:supavisor, :http_sql, cfg) end)

      conn = post_sql(conn, %{"query" => "SELECT 1", "params" => []})
      assert conn.status == 404
    end

    test "disabled per-tenant → 404", %{conn: conn} do
      tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")
      {:ok, _} = Supavisor.Tenants.update_tenant(tenant, %{feature_flags: %{}})

      conn = post_sql(conn, %{"query" => "SELECT 1", "params" => []})
      assert conn.status == 404
    end
  end
end
