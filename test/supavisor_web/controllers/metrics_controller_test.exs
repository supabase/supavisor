defmodule SupavisorWeb.MetricsControllerTest do
  use SupavisorWeb.ConnCase, async: false
  alias Supavisor.Support.Cluster
  alias Postgrex, as: P

  @tag cluster: true
  test "exporting metrics", %{conn: conn} do
    {:ok, _pid, node2} = Cluster.start_node()

    Node.connect(node2)

    conn =
      conn
      |> auth
      |> get(Routes.metrics_path(conn, :index))

    assert conn.status == 200
    assert conn.resp_body =~ "region=\"eu\""
    assert conn.resp_body =~ "region=\"usa\""
  end

  test "invalid jwt", %{conn: conn} do
    token = "invalid"

    conn =
      conn
      |> auth(token)
      |> get(Routes.metrics_path(conn, :index))

    assert conn.status == 403
  end

  test "exporting tenant metrics", %{conn: conn} do
    tenant_id = "proxy_tenant_ps_enabled"
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    # Establish a connection to generate metrics data for the tenant
    assert {:ok, proxy} =
             Postgrex.start_link(
               hostname: db_conf[:hostname],
               port: Application.get_env(:supavisor, :proxy_port_transaction),
               database: db_conf[:database],
               password: db_conf[:password],
               username: db_conf[:username] <> "." <> tenant_id
             )

    # Execute a simple query to generate activity
    P.query!(proxy, "SELECT 1", [])

    # Cache the tenant metrics before fetching them
    Supavisor.Monitoring.PromEx.do_cache_tenants_metrics()

    conn =
      conn
      |> auth
      |> get(Routes.metrics_path(conn, :tenant, tenant_id))

    assert conn.status == 200
    assert conn.resp_body =~ "tenant=\"#{tenant_id}\""

    GenServer.stop(proxy)
  end

  test "instrumenting and tunning cluster metrics collection process", %{conn: conn} do
    conn
    |> auth
    |> get(Routes.metrics_path(conn, :index))

    assert :metrics_handler = :proc_lib.get_label(self())

    [min_heap_size: new_min_heap_words, fullsweep_after: new_fullsweep_after] =
      Process.info(self(), [:min_heap_size, :fullsweep_after])

    expected_words = Supavisor.Helpers.mb_to_words(100)

    # Erlang rounds up to next valid heap size, so check it's at least expected
    # and not more than 50% larger (accounting for heap size rounding)
    assert new_min_heap_words >= expected_words
    assert new_min_heap_words <= expected_words * 1.5

    assert new_fullsweep_after == 0
  end

  test "setting values to negatives ones disables metrics collection process tunning", %{
    conn: conn
  } do
    old_env = Application.get_env(:supavisor, SupavisorWeb.MetricsController)

    Application.put_env(:supavisor, SupavisorWeb.MetricsController,
      index_min_heap_size_mb: -1,
      index_fullsweep_after: -1
    )

    [min_heap_size: old_heap_words, fullsweep_after: old_fullsweep_after] =
      Process.info(self(), [:min_heap_size, :fullsweep_after])

    conn
    |> auth
    |> get(Routes.metrics_path(conn, :index))

    [min_heap_size: new_min_heap_words, fullsweep_after: new_fullsweep_after] =
      Process.info(self(), [:min_heap_size, :fullsweep_after])

    assert new_min_heap_words == old_heap_words
    assert new_fullsweep_after == old_fullsweep_after
    Application.put_env(:supavisor, SupavisorWeb.MetricsController, old_env)
  end

  test "instrumenting tenant metrics collection", %{conn: conn} do
    tenant_id = "proxy_tenant_id"

    conn
    |> auth
    |> get(Routes.metrics_path(conn, :tenant, tenant_id))

    assert {:tenant_metrics_handler, ^tenant_id} = :proc_lib.get_label(self())
  end

  defp auth(conn, bearer \\ gen_token()) do
    put_req_header(conn, "authorization", "Bearer " <> bearer)
  end

  defp gen_token(secret \\ Application.fetch_env!(:supavisor, :metrics_jwt_secret)) do
    Supavisor.Jwt.Token.gen!(secret)
  end
end
