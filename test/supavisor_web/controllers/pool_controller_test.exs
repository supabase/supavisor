defmodule SupavisorWeb.PoolControllerTest do
  use SupavisorWeb.ConnCase, async: false

  require Supavisor

  import Supavisor.TenantsFixtures

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

    test "returns an empty list for a tenant with no pools", %{conn: conn} do
      assert %{pools: [], errors: %{}} =
               conn
               |> get(~p"/api/tenants/no_such_tenant/pools")
               |> json_response(200)
               |> assert_schema("PoolList")
    end

    test "lists the tenant's pools with id, token and counts", %{conn: conn} do
      start_pool!(pool_id([]))

      assert %{pools: [pool], errors: %{}} =
               conn
               |> get(~p"/api/tenants/#{@tenant}/pools")
               |> json_response(200)
               |> assert_schema("PoolList")

      assert pool.id.tenant == @tenant
      assert pool.id.user == "postgres"
      assert pool.id.mode == "transaction"
      assert pool.id.database == "supavisor_test"
      assert is_binary(pool.token) and pool.token != ""
      assert pool.node == to_string(node())
      assert pool.host == "localhost"
      assert pool.port == 6432
      assert is_integer(pool.clients)
      assert %{idle: idle, checked_out: checked_out} = pool.connections
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

  defp gen_token do
    Supavisor.Jwt.Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))
  end
end
