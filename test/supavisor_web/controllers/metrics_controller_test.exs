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

  def handle_jwt_auth_event(event, measurements, meta, {pid, ref}) do
    send(pid, {ref, event, measurements, meta})
  end

  defp attach_jwt_auth_handler do
    ref = make_ref()

    :telemetry.attach_many(
      {ref, :jwt_auth},
      [[:supavisor, :jwt_auth, :ok], [:supavisor, :jwt_auth, :rejected]],
      &__MODULE__.handle_jwt_auth_event/4,
      {self(), ref}
    )

    on_exit(fn -> :telemetry.detach({ref, :jwt_auth}) end)

    ref
  end

  test "emits jwt_auth ok for a valid token on the metrics pipeline", %{conn: conn} do
    ref = attach_jwt_auth_handler()

    assert conn |> auth() |> get(Routes.metrics_path(conn, :index)) |> Map.fetch!(:status) == 200

    assert_receive {^ref, [:supavisor, :jwt_auth, :ok], %{count: 1},
                    %{method: :hmac, pipeline: :metrics}}

    refute_received {^ref, [:supavisor, :jwt_auth, :rejected], _, _}
  end

  test "emits jwt_auth rejected (method :unknown, no parsable alg) for an invalid token", %{
    conn: conn
  } do
    ref = attach_jwt_auth_handler()

    assert conn
           |> auth("invalid")
           |> get(Routes.metrics_path(conn, :index))
           |> Map.fetch!(:status) ==
             403

    assert_receive {^ref, [:supavisor, :jwt_auth, :rejected], %{count: 1},
                    %{method: :unknown, pipeline: :metrics, reason: :expected_header_map}}

    refute_received {^ref, [:supavisor, :jwt_auth, :ok], _, _}
  end

  test "emits jwt_auth rejected :invalid_authorization_header without a token", %{
    conn: conn
  } do
    ref = attach_jwt_auth_handler()

    assert get(conn, Routes.metrics_path(conn, :index)).status == 403

    assert_receive {^ref, [:supavisor, :jwt_auth, :rejected], %{count: 1},
                    %{
                      method: :unknown,
                      pipeline: :metrics,
                      reason: :invalid_authorization_header
                    }}
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

  test "tunning cluster metrics collection process", %{conn: conn} do
    default_min_heap_size = :erlang.system_info(:min_heap_size) |> elem(1)
    default_fullsweep_after = :erlang.system_info(:fullsweep_after) |> elem(1)
    expected_words = Supavisor.Helpers.mb_to_words(100)

    assert_mhs_and_fsa = fn
      {min_mhs, max_mhs}, fsa ->
        assert [min_heap_size: mhs, fullsweep_after: ^fsa] =
                 Process.info(self(), [:min_heap_size, :fullsweep_after])

        assert mhs >= min_mhs
        assert mhs <= max_mhs

      mhs, fsa ->
        assert [min_heap_size: ^mhs, fullsweep_after: ^fsa] =
                 Process.info(self(), [:min_heap_size, :fullsweep_after])
    end

    conn
    |> auth
    |> get(Routes.metrics_path(conn, :index))

    assert_mhs_and_fsa.(default_min_heap_size, default_fullsweep_after)

    SupavisorWeb.MetricsController.configure_tune_index_proc(_min_heap_size_mb = 100, 0)

    # we need a new process as if it was a new connection, as the changes apply to NEW conns
    parent = self()

    spawn_link(fn ->
      conn
      |> auth
      |> get(Routes.metrics_path(conn, :index))

      # Erlang rounds up to next valid heap size, so check it's at least expected
      # and not more than 50% larger (accounting for heap size rounding)
      assert_mhs_and_fsa.({expected_words, expected_words * 1.5}, 0)
      send(parent, :done)
    end)

    assert_receive :done, 2000

    SupavisorWeb.MetricsController.configure_tune_index_proc(nil, nil)
  end

  test "restoring cluster metrics collection process to defaults", %{
    conn: conn
  } do
    default_min_heap_size = :erlang.system_info(:min_heap_size) |> elem(1)
    default_fullsweep_after = :erlang.system_info(:fullsweep_after) |> elem(1)

    conn
    |> auth
    |> get(Routes.metrics_path(conn, :index))

    SupavisorWeb.MetricsController.configure_tune_index_proc(
      _min_heap_size_mb = 100,
      _fullsweep_after = 0
    )

    SupavisorWeb.MetricsController.configure_tune_index_proc(nil, nil)

    # we need a new process as if it was a new connection, as the changes apply to NEW conns
    parent = self()

    spawn_link(fn ->
      conn
      |> auth
      |> get(Routes.metrics_path(conn, :index))

      assert [min_heap_size: ^default_min_heap_size, fullsweep_after: ^default_fullsweep_after] =
               Process.info(self(), [:min_heap_size, :fullsweep_after])

      send(parent, :done)
    end)

    assert_receive :done, 2000
  end

  test "instrumenting metrics collection", %{conn: conn} do
    tenant_id = "proxy_tenant_id"

    conn
    |> auth
    |> get(Routes.metrics_path(conn, :tenant, tenant_id))

    assert {:metrics_handler, ^tenant_id} = :proc_lib.get_label(self())

    conn
    |> auth
    |> get(Routes.metrics_path(conn, :index))

    assert :metrics_handler = :proc_lib.get_label(self())
  end

  defp auth(conn, bearer \\ gen_token()) do
    put_req_header(conn, "authorization", "Bearer " <> bearer)
  end

  defp gen_token(secret \\ Application.fetch_env!(:supavisor, :metrics_jwt_secret)) do
    Supavisor.JWT.SharedSecret.Token.gen!(secret)
  end
end
