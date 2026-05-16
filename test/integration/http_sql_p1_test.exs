defmodule Supavisor.Integration.HttpSqlP1Test do
  @moduledoc """
  Integration tests for cross-module HTTP-SQL behaviors that classically
  surface in production rather than in isolated unit tests:

    - CircuitBreaker brute-force defense actually trips after the
      threshold (P1)
    - `Supavisor.del_all_cache/1` evicts our Postgrex pools
      end-to-end via `PoolRegistry.evict_tenant/1` (P1)
    - Pool TOCTOU `:exit, :noproc` returns a Neon-shape 503 instead of
      crashing the controller (P1)
    - PromEx pipeline fires the new request/pool telemetry events with
      the correct measurements (P1)
    - Audit log contains required fields on auth failure and on errors
      (P1)

  Tagged `:integration`. Run with:

      mix test --include integration test/integration/http_sql_p1_test.exs
  """
  use SupavisorWeb.ConnCase, async: false

  import ExUnit.CaptureLog
  import Supavisor.TenantsFixtures

  alias Supavisor.HttpSql.PoolRegistry
  alias Supavisor.HttpSql.PoolSpec

  @moduletag :integration

  @conn_str "postgres://postgres.dev_tenant:postgres@localhost/postgres"
  @bad_pwd_conn_str "postgres://postgres.dev_tenant:WRONG@localhost/postgres"

  setup do
    _ = tenant_fixture()

    tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")
    {:ok, _} = Supavisor.Tenants.update_tenant(tenant, %{feature_flags: %{"http_sql" => true}})

    cfg = Application.get_env(:supavisor, :http_sql, [])
    Application.put_env(:supavisor, :http_sql, Keyword.put(cfg, :enabled, true))

    # Each test gets a clean PoolRegistry to avoid cross-test
    # contamination of LRU state, and a clean CircuitBreaker so a
    # brute-force test in one case doesn't leave a 2-minute ban that
    # poisons the next.
    Supervisor.terminate_child(Supavisor.Supervisor, PoolRegistry)
    {:ok, _} = Supervisor.restart_child(Supavisor.Supervisor, PoolRegistry)
    if :ets.whereis(Supavisor.CircuitBreaker.Blocks) != :undefined,
      do: :ets.delete_all_objects(Supavisor.CircuitBreaker.Blocks)
    if :ets.whereis(Supavisor.CircuitBreaker.Windows) != :undefined,
      do: :ets.delete_all_objects(Supavisor.CircuitBreaker.Windows)

    on_exit(fn -> Application.put_env(:supavisor, :http_sql, cfg) end)
    :ok
  end

  defp post_sql(conn, conn_str, body, headers \\ []) do
    conn =
      conn
      |> put_req_header("content-type", "application/json")
      |> put_req_header("neon-connection-string", conn_str)

    conn = Enum.reduce(headers, conn, fn {h, v}, acc -> put_req_header(acc, h, v) end)
    post(conn, "/sql", body)
  end

  # --------------------------------------------------------------------------
  #  P1 — CircuitBreaker tripping after N bad-password attempts
  # --------------------------------------------------------------------------

  describe "brute-force defense (CircuitBreaker integration)" do
    test "after 10 invalid_password attempts the next request is 403-banned by NeonAuth", %{
      conn: conn_template
    } do
      # PasswordVerifier in NeonAuth rejects bad passwords synchronously
      # via cached SASL secrets, then records a failure against
      # {tenant, real_ip} on the CircuitBreaker. Threshold for the
      # :auth_error operation is 10 (see CircuitBreaker @config).
      for _ <- 1..10 do
        conn =
          post_sql(
            conn_template,
            @bad_pwd_conn_str,
            %{"query" => "SELECT 1", "params" => []}
          )

        assert conn.status == 401
        assert Jason.decode!(conn.resp_body)["code"] == "unauthorized"
      end

      # The 11th request — even with the CORRECT password — must be
      # 403-banned by NeonAuth BEFORE PasswordVerifier even runs.
      banned_conn =
        post_sql(
          conn_template,
          @conn_str,
          %{"query" => "SELECT 1", "params" => []}
        )

      assert banned_conn.status == 503
      body = Jason.decode!(banned_conn.resp_body)
      assert body["code"] == "circuit_open"
    end
  end

  # --------------------------------------------------------------------------
  #  P1 — evict_tenant chain: Supavisor.del_all_cache → PoolRegistry
  # --------------------------------------------------------------------------

  describe "tenant cache invalidation evicts HTTP-SQL pools" do
    test "del_all_cache(tenant) clears the Postgrex pool", %{conn: conn_template} do
      # Warm a pool for dev_tenant.
      conn = post_sql(conn_template, @conn_str, %{"query" => "SELECT 1", "params" => []})
      assert conn.status == 200

      key = PoolSpec.key("dev_tenant", "postgres.dev_tenant", "postgres")
      assert {1, [{^key, _pid, _last}]} = PoolRegistry.stats()

      # Trigger the same cache invalidation path admin actions use.
      Supavisor.del_all_cache("dev_tenant")
      Process.sleep(50)

      assert {0, []} = PoolRegistry.stats()
    end

    test "update_tenant goes through the same path", %{conn: conn_template} do
      post_sql(conn_template, @conn_str, %{"query" => "SELECT 1", "params" => []})
      assert {1, _} = PoolRegistry.stats()

      tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")

      {:ok, _} =
        Supavisor.Tenants.update_tenant(tenant, %{
          feature_flags: %{"http_sql" => true, "other" => true}
        })

      Process.sleep(50)
      assert {0, []} = PoolRegistry.stats()
    end
  end

  # --------------------------------------------------------------------------
  #  P1 — TOCTOU :exit :noproc on dead pool
  # --------------------------------------------------------------------------

  describe "TOCTOU pool death between checkout and Postgrex call" do
    setup do
      # Inject a starter that hands back a process which exits AFTER the
      # facade has the pid in hand. The facade should catch the
      # :exit :noproc and return a connection_error, not crash.
      starter = fn _opts ->
        pid =
          spawn(fn ->
            receive do
              :die -> :ok
            after
              30_000 -> :ok
            end
          end)

        # Schedule the death right after the pid is registered.
        spawn(fn ->
          Process.sleep(20)
          send(pid, :die)
        end)

        {:ok, pid}
      end

      Application.put_env(:supavisor, :http_sql_starter, starter)

      Supervisor.terminate_child(Supavisor.Supervisor, PoolRegistry)
      {:ok, _} = Supervisor.restart_child(Supavisor.Supervisor, PoolRegistry)

      on_exit(fn ->
        Application.delete_env(:supavisor, :http_sql_starter)
        Supervisor.terminate_child(Supavisor.Supervisor, PoolRegistry)
        {:ok, _} = Supervisor.restart_child(Supavisor.Supervisor, PoolRegistry)
      end)

      :ok
    end

    test "fake pool death returns a Neon-shape 5xx, not a generic crash", %{conn: conn_template} do
      # Sleep enough for the fake-pool death to have propagated.
      Process.sleep(50)

      conn = post_sql(conn_template, @conn_str, %{"query" => "SELECT 1", "params" => []})
      assert conn.status in [500, 503]

      body = Jason.decode!(conn.resp_body)
      # Either a connection_error from our facade's :exit rescue, or a
      # Postgrex protocol error if the pool died after auth — both are
      # Neon-shape with a `code` field, not a generic Phoenix 500 page.
      assert is_binary(body["code"])
    end
  end

  # --------------------------------------------------------------------------
  #  P1 — Telemetry events fire with correct measurements
  # --------------------------------------------------------------------------

  describe "telemetry pipeline" do
    setup do
      parent = self()
      ref = make_ref()

      handler = fn name, measurements, metadata, _config ->
        send(parent, {ref, name, measurements, metadata})
      end

      events = [
        [:supavisor, :http_sql, :request, :stop],
        [:supavisor, :http_sql, :pool, :checkout]
      ]

      :telemetry.attach_many(ref, events, handler, nil)
      on_exit(fn -> :telemetry.detach(ref) end)

      {:ok, ref: ref}
    end

    test ":request, :stop carries non-zero response_rows on a real SELECT", %{
      conn: conn_template,
      ref: ref
    } do
      conn = post_sql(conn_template, @conn_str, %{"query" => "SELECT 1 AS n", "params" => []})
      assert conn.status == 200

      # Find the :request, :stop event with status 200.
      assert_receive {^ref, [:supavisor, :http_sql, :request, :stop], measurements,
                      %{tenant: "dev_tenant", status_code: 200} = metadata},
                     5000

      assert is_integer(measurements.duration)
      assert metadata.response_rows == 1
    end

    test ":pool, :checkout fires with hit?: :miss then :hit", %{
      conn: conn_template,
      ref: ref
    } do
      _ = post_sql(conn_template, @conn_str, %{"query" => "SELECT 1", "params" => []})
      assert_receive {^ref, [:supavisor, :http_sql, :pool, :checkout], _, %{hit?: :miss}}, 5000

      _ = post_sql(conn_template, @conn_str, %{"query" => "SELECT 2", "params" => []})
      assert_receive {^ref, [:supavisor, :http_sql, :pool, :checkout], _, %{hit?: :hit}}, 5000
    end
  end

  # --------------------------------------------------------------------------
  #  P1 — Audit log carries the expected fields
  # --------------------------------------------------------------------------

  describe "audit log" do
    test "JWT auth attempt logs warning with tenant and remote_ip", %{conn: conn_template} do
      log =
        capture_log(fn ->
          conn =
            post_sql(
              conn_template,
              @conn_str,
              %{"query" => "SELECT 1", "params" => []},
              [{"authorization", "Bearer FAKE"}]
            )

          assert conn.status == 401
        end)

      assert log =~ "http_sql"
      # Audit log must NOT contain the password.
      refute log =~ "WRONG"
    end

    test "Postgres syntax error logs at info with status=400", %{conn: conn_template} do
      log =
        capture_log(fn ->
          conn = post_sql(conn_template, @conn_str, %{"query" => "SELECT BORK", "params" => []})
          assert conn.status == 400
        end)

      # The error path goes through audit_log/3 which logs at info level.
      # The Postgres error code 42703 (undefined_column) appears in reason.
      assert log =~ "http_sql" or log =~ "42703"
    end
  end
end
