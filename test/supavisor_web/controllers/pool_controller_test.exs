defmodule SupavisorWeb.PoolControllerTest do
  use SupavisorWeb.ConnCase, async: false

  require Supavisor

  import Supavisor.TenantsFixtures
  import Supavisor.Asserts, only: [assert_eventually: 3]

  alias SupavisorWeb.PoolPid

  @tenant "pool_controller_tenant"
  @secret %Supavisor.Secrets.PasswordSecrets{user: "postgres", password: "postgres"}

  defp pool_id(opts) do
    Supavisor.id(
      type: :single,
      tenant: @tenant,
      user: "postgres",
      mode: opts[:mode] || :transaction,
      db: opts[:db] || "supavisor_test",
      search_path: nil
    )
  end

  defp start_pool!(id) do
    {:ok, _pid} = Supavisor.start(id, @secret)
    on_exit(fn -> Supavisor.stop(id) end)
    id
  end

  describe "GET /api/tenants/:external_id/pools" do
    setup %{conn: conn} do
      tenant_fixture(%{external_id: @tenant})
      {:ok, conn: put_req_header(conn, "authorization", "Bearer " <> gen_token())}
    end

    test "returns 404 for a tenant that does not exist", %{conn: conn} do
      assert %{"error" => "not found"} =
               conn
               |> get(~p"/api/tenants/no_such_tenant/pools")
               |> json_response(404)
    end

    test "returns an empty list for a tenant without running pools", %{conn: conn} do
      assert %{pools: [], errors: %{}} =
               conn
               |> get(~p"/api/tenants/#{@tenant}/pools")
               |> json_response(200)
               |> assert_schema("PoolList")
    end

    test "lists the tenant's pools with id, pid, status and counts", %{conn: conn} do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)

      assert %{pools: [pool], errors: %{}} =
               conn
               |> get(~p"/api/tenants/#{@tenant}/pools")
               |> json_response(200)
               |> assert_schema("PoolList")

      assert pool.id.tenant == @tenant
      assert pool.id.user == "postgres"
      assert pool.id.mode == "transaction"
      assert pool.id.db == "supavisor_test"
      assert PoolPid.decode(pool.pid) == {:ok, sup}
      assert pool.pid_label == inspect(sup)
      assert pool.status == "active"
      assert pool.node == to_string(node())
      assert pool.db_host == "localhost"
      assert pool.db_port == 6432
      assert is_integer(pool.clients)
      assert %{idle: idle, checked_out: checked_out} = pool.db_connections
      assert is_integer(idle) and is_integer(checked_out)
    end

    test "lists every pool of the tenant", %{conn: conn} do
      start_pool!(pool_id(mode: :transaction))
      start_pool!(pool_id(mode: :session))

      assert %{pools: pools} =
               conn
               |> get(~p"/api/tenants/#{@tenant}/pools")
               |> json_response(200)
               |> assert_schema("PoolList")

      assert length(pools) == 2
    end

    test "reports a node that fails to answer as unreachable", %{conn: conn} do
      :meck.new(Supavisor.Ops, [:passthrough, :no_link])
      on_exit(fn -> :meck.unload(Supavisor.Ops) end)
      :meck.expect(Supavisor.Ops, :list_pools_local, fn _tenant -> raise "boom" end)

      assert %{pools: [], errors: errors} =
               conn
               |> get(~p"/api/tenants/#{@tenant}/pools")
               |> json_response(200)
               |> assert_schema("PoolList")

      assert errors == %{to_string(node()) => "unreachable"}
    end

    test "requires authorization" do
      assert build_conn()
             |> get(~p"/api/tenants/#{@tenant}/pools")
             |> response(403)
    end
  end

  describe "DELETE /api/tenants/:external_id/pools" do
    setup %{conn: conn} do
      tenant_fixture(%{external_id: @tenant})

      conn =
        conn
        |> put_req_header("authorization", "Bearer " <> gen_token())
        |> put_req_header("content-type", "application/json")

      {:ok, conn: conn}
    end

    test "stops the pool the pid identifies", %{conn: conn} do
      id = start_pool!(pool_id(mode: :transaction))
      other = start_pool!(pool_id(mode: :session))
      sup = Supavisor.get_global_sup(id)
      other_sup = Supavisor.get_global_sup(other)
      assert is_pid(sup) and is_pid(other_sup)

      assert conn
             |> delete(~p"/api/tenants/#{@tenant}/pools", stop_body(sup, timeout: 5_000))
             |> response(204)

      refute Process.alive?(sup)
      assert Supavisor.get_global_sup(id) == nil
      # The same process: the other pool was neither stopped nor restarted.
      assert Process.alive?(other_sup)
      assert Supavisor.get_global_sup(other) == other_sup
    end

    test "accepts the pid returned by the pool list", %{conn: conn} do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)

      %{"pools" => [%{"pid" => pid}]} =
        conn |> get(~p"/api/tenants/#{@tenant}/pools") |> json_response(200)

      assert conn
             |> delete(~p"/api/tenants/#{@tenant}/pools", Jason.encode!(%{pid: pid}))
             |> response(204)

      refute Process.alive?(sup)
    end

    test "returns 202 when the pool is still shutting down at the timeout", %{conn: conn} do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)
      # The Terminator's call to the suspended poolboy blocks until the supervisor
      # kills it after its 5s shutdown timeout.
      :sys.suspend(Supavisor.get_local_pool(id))

      assert conn
             |> delete(~p"/api/tenants/#{@tenant}/pools", stop_body(sup, timeout: 100))
             |> response(202) == ""

      assert_eventually(10, 1_000, fn -> not Process.alive?(sup) end)
    end

    test "returns 404 for a pool that is not running", %{conn: conn} do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      :ok = Supervisor.stop(sup)
      # The registry drops the pool shortly after it exits.
      assert_eventually(10, 100, fn -> Supavisor.Ops.list_pools_local(@tenant) == [] end)

      assert %{"error" => "not found"} =
               conn
               |> delete(~p"/api/tenants/#{@tenant}/pools", stop_body(sup))
               |> json_response(404)
    end

    test "returns 404 for another tenant's pool without stopping it", %{conn: conn} do
      other_tenant = "pool_controller_other_tenant"
      tenant_fixture(%{external_id: other_tenant})
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)

      assert %{"error" => "not found"} =
               conn
               |> delete(~p"/api/tenants/#{other_tenant}/pools", stop_body(sup))
               |> json_response(404)

      assert Process.alive?(sup)
      assert Supavisor.get_global_sup(id) == sup
    end

    test "returns 404 for a tenant that does not exist", %{conn: conn} do
      id = start_pool!(pool_id([]))
      sup = Supavisor.get_global_sup(id)
      assert is_pid(sup)

      assert %{"error" => "not found"} =
               conn
               |> delete(~p"/api/tenants/no_such_tenant/pools", stop_body(sup))
               |> json_response(404)

      assert Process.alive?(sup)
    end

    test "returns 503 when the pool's node is unreachable", %{conn: conn} do
      :meck.new(Supavisor.Ops, [:passthrough, :no_link])
      on_exit(fn -> :meck.unload(Supavisor.Ops) end)

      :meck.expect(Supavisor.Ops, :stop_pool, fn _tenant, _sup, _timeout ->
        {:error, :node_unreachable}
      end)

      assert %{"error" => "node unreachable"} =
               conn
               |> delete(~p"/api/tenants/#{@tenant}/pools", stop_body(self()))
               |> json_response(503)
    end

    test "returns 422 for a pid that does not decode", %{conn: conn} do
      assert %{"error" => "invalid pid"} =
               conn
               |> delete(~p"/api/tenants/#{@tenant}/pools", Jason.encode!(%{pid: "garbage"}))
               |> json_response(422)
    end

    test "returns 422 for an encoded term that is not a pid", %{conn: conn} do
      not_a_pid = :ok |> :erlang.term_to_binary() |> Base.url_encode64(padding: false)

      assert %{"error" => "invalid pid"} =
               conn
               |> delete(~p"/api/tenants/#{@tenant}/pools", Jason.encode!(%{pid: not_a_pid}))
               |> json_response(422)
    end

    test "returns 422 without a pid", %{conn: conn} do
      assert %{"errors" => [%{"source" => %{"pointer" => "/pid"}}]} =
               conn
               |> delete(~p"/api/tenants/#{@tenant}/pools", "{}")
               |> json_response(422)
    end

    test "returns 422 when timeout is not positive", %{conn: conn} do
      assert %{"errors" => [%{"source" => %{"pointer" => "/timeout"}}]} =
               conn
               |> delete(~p"/api/tenants/#{@tenant}/pools", stop_body(self(), timeout: 0))
               |> json_response(422)
    end

    test "requires authorization" do
      assert build_conn()
             |> put_req_header("content-type", "application/json")
             |> delete(~p"/api/tenants/#{@tenant}/pools", stop_body(self()))
             |> response(403)
    end
  end

  describe "POST /api/rebalance" do
    setup %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer " <> gen_token())
        |> put_req_header("content-type", "application/json")

      {:ok, conn: conn}
    end

    test "moves no pools when the cluster has a single node", %{conn: conn} do
      assert %{moves: [], errors: %{}} =
               conn
               |> post(~p"/api/rebalance", "{}")
               |> json_response(200)
               |> assert_schema("Rebalance")
    end

    test "returns 422 when max_concurrency is not positive", %{conn: conn} do
      assert %{"errors" => [%{"source" => %{"pointer" => "/max_concurrency"}}]} =
               conn
               |> post(~p"/api/rebalance", Jason.encode!(%{max_concurrency: 0}))
               |> json_response(422)
    end

    test "returns 422 when dry_run is not a boolean", %{conn: conn} do
      assert %{"errors" => [%{"source" => %{"pointer" => "/dry_run"}}]} =
               conn
               |> post(~p"/api/rebalance", Jason.encode!(%{dry_run: "yes"}))
               |> json_response(422)
    end
  end

  defp stop_body(pid, params \\ []) do
    params |> Map.new() |> Map.put(:pid, PoolPid.encode(pid)) |> Jason.encode!()
  end

  defp gen_token do
    Supavisor.Jwt.Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))
  end
end
