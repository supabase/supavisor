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

  test "instrumenting cluster metrics collection", %{conn: conn} do
    conn
    |> auth
    |> get(Routes.metrics_path(conn, :index))

    assert :metrics_handler = :proc_lib.get_label(self())

    {:min_heap_size, new_min_heap_words} = Process.info(self(), :min_heap_size)
    expected_words = percent_of_total_available_memory_in_words(0.03)

    assert_in_delta new_min_heap_words, expected_words, expected_words * 0.1
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

  def percent_of_total_available_memory_in_words(percent) do
    total_memory_bytes = :memsup.get_system_memory_data()[:total_memory]
    div(round(total_memory_bytes * percent), :erlang.system_info(:wordsize))
  end
end
