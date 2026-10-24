defmodule Supavisor.Integration.HttpSqlTest do
  use SupavisorWeb.ConnCase, async: false

  @moduletag integration: true

  @tenant "proxy_tenant_ps_enabled"

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    conn_string =
      "postgresql://#{db_conf[:username]}.#{@tenant}:#{db_conf[:password]}@localhost/#{db_conf[:database]}"

    {:ok, conn_string: conn_string, db_conf: db_conf}
  end

  # Like the driver, which sends JSON without a content type.
  defp sql(conn, conn_string, body, headers \\ []) do
    conn
    |> put_req_header("content-type", "text/plain;charset=UTF-8")
    |> put_req_header("neon-connection-string", conn_string)
    |> then(&Enum.reduce(headers, &1, fn {k, v}, conn -> put_req_header(conn, k, v) end))
    |> post("/sql", JSON.encode!(body))
  end

  test "runs a query with params", %{conn: conn, conn_string: conn_string} do
    conn =
      sql(conn, conn_string, %{
        "query" => "SELECT $1::int + 1 AS n, $2::text AS t, $3::bool AS b",
        "params" => ["41", nil, true]
      })

    assert %{
             "command" => "SELECT",
             "rowCount" => 1,
             "rowAsArray" => true,
             "rows" => [["42", nil, "t"]],
             "fields" => [
               %{
                 "name" => "n",
                 "tableID" => 0,
                 "columnID" => 0,
                 "dataTypeID" => 23,
                 "dataTypeSize" => 4,
                 "dataTypeModifier" => -1,
                 "format" => "text"
               },
               %{"name" => "t", "dataTypeID" => 25},
               %{"name" => "b", "dataTypeID" => 16}
             ]
           } = json_response(conn, 200)

    assert get_resp_header(conn, "access-control-allow-origin") == ["*"]
  end

  test "returns values in Postgres text format", %{conn: conn, conn_string: conn_string} do
    conn =
      sql(conn, conn_string, %{
        "query" =>
          "SELECT true, '\\x0102'::bytea, ARRAY[1,2], '2026-01-02'::date, '{\"a\":1}'::jsonb"
      })

    assert %{"rows" => [["t", "\\x0102", "{1,2}", "2026-01-02", "{\"a\": 1}"]]} =
             json_response(conn, 200)
  end

  test "returns a Postgres error as 400 with its fields", %{conn: conn, conn_string: conn_string} do
    conn = sql(conn, conn_string, %{"query" => "SELECT * FROM does_not_exist"})

    assert %{"code" => "42P01", "severity" => "ERROR", "position" => "15", "message" => message} =
             json_response(conn, 400)

    assert message =~ "does_not_exist"
  end

  test "decodes the connection string and its options", %{conn: conn, db_conf: db_conf} do
    password = URI.encode(db_conf[:password], fn _ -> false end)

    conn_string =
      "postgresql://#{db_conf[:username]}:#{password}@localhost/#{db_conf[:database]}?options=reference%3D#{@tenant}"

    assert %{"rows" => [["1"]]} =
             conn |> sql(conn_string, %{"query" => "SELECT 1"}) |> json_response(200)
  end

  test "passes the client's IP to Supavisor", %{conn: conn, conn_string: conn_string} do
    key = {@tenant, "10.0.0.1"}
    Supavisor.CircuitBreaker.open_local(key, :auth_error, System.system_time(:second) + 60)
    on_exit(fn -> Supavisor.CircuitBreaker.clear(key, :auth_error) end)

    # Logins from that IP are blocked, so its requests are turned away.
    conn = sql(%{conn | remote_ip: {10, 0, 0, 1}}, conn_string, %{"query" => "SELECT 1"})
    assert %{"message" => message} = json_response(conn, 400)
    assert message =~ "ECIRCUITBREAKER"
  end

  test "rejects a wrong password", %{conn: conn, db_conf: db_conf} do
    conn_string =
      "postgresql://#{db_conf[:username]}.#{@tenant}:wrong@localhost/#{db_conf[:database]}"

    assert %{"code" => "28P01"} =
             conn |> sql(conn_string, %{"query" => "SELECT 1"}) |> json_response(400)
  end

  describe "batches" do
    setup %{conn_string: conn_string} do
      table = "http_sql_#{System.unique_integer([:positive])}"
      conn = sql(build_conn(), conn_string, %{"query" => "CREATE TABLE #{table} (n int UNIQUE)"})
      assert %{"command" => "CREATE"} = json_response(conn, 200)

      on_exit(fn ->
        sql(build_conn(), conn_string, %{"query" => "DROP TABLE #{table}"})
      end)

      {:ok, table: table}
    end

    test "run in a transaction", %{conn: conn, conn_string: conn_string, table: table} do
      body = %{
        "queries" => [
          %{"query" => "INSERT INTO #{table} VALUES ($1), ($2)", "params" => ["1", "2"]},
          %{"query" => "SELECT current_setting('transaction_isolation')"}
        ]
      }

      conn = sql(conn, conn_string, body, [{"neon-batch-isolation-level", "Serializable"}])

      assert %{
               "results" => [
                 %{"command" => "INSERT", "rowCount" => 2},
                 %{"rows" => [["serializable"]]}
               ]
             } = json_response(conn, 200)
    end

    test "take the transaction's options from the headers", %{
      conn: conn,
      conn_string: conn_string
    } do
      body = %{
        "queries" => [
          %{
            "query" =>
              "SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only'), current_setting('transaction_deferrable')"
          }
        ]
      }

      headers = [
        {"neon-batch-isolation-level", "RepeatableRead"},
        {"neon-batch-read-only", "true"},
        {"neon-batch-deferrable", "true"}
      ]

      assert %{"results" => [%{"rows" => [["repeatable read", "on", "on"]]}]} =
               conn |> sql(conn_string, body, headers) |> json_response(200)
    end

    test "are rolled back when a query fails", %{
      conn: conn,
      conn_string: conn_string,
      table: table
    } do
      body = %{
        "queries" => [
          %{"query" => "INSERT INTO #{table} VALUES (1)"},
          %{"query" => "INSERT INTO #{table} VALUES (1)"}
        ]
      }

      assert %{"code" => "23505"} = conn |> sql(conn_string, body) |> json_response(400)

      # Nothing was kept, and the connection went back to the pool clean.
      conn = sql(build_conn(), conn_string, %{"query" => "SELECT count(*) FROM #{table}"})
      assert %{"rows" => [["0"]]} = json_response(conn, 200)
    end
  end

  test "rejects a body over 8MB", %{conn: conn, conn_string: conn_string} do
    query = "SELECT '#{String.duplicate("x", 8_000_000)}'"

    assert %{"message" => "request body too large"} =
             conn |> sql(conn_string, %{"query" => query}) |> json_response(413)
  end

  test "stops a response over the limit", %{conn: conn, conn_string: conn_string} do
    Application.put_env(:supavisor, :http_sql_max_response_bytes, 1000)
    on_exit(fn -> Application.delete_env(:supavisor, :http_sql_max_response_bytes) end)

    conn = sql(conn, conn_string, %{"query" => "SELECT generate_series(1, 1000)"})
    assert %{"message" => "response is too large (max is 1000 bytes)"} = json_response(conn, 507)
  end

  test "stops a row over the limit", %{conn: conn, conn_string: conn_string} do
    Application.put_env(:supavisor, :http_sql_max_response_bytes, 1000)
    on_exit(fn -> Application.delete_env(:supavisor, :http_sql_max_response_bytes) end)

    conn = sql(conn, conn_string, %{"query" => "SELECT repeat('x', 10000000)"})
    assert %{"message" => "response is too large (max is 1000 bytes)"} = json_response(conn, 507)
  end

  test "answers CORS preflight requests", %{conn: conn} do
    conn = options(conn, "/sql")

    assert response(conn, 200)
    assert get_resp_header(conn, "access-control-allow-origin") == ["*"]
    assert [headers] = get_resp_header(conn, "access-control-allow-headers")
    assert headers =~ "Neon-Connection-String"
  end
end
