defmodule SupavisorWeb.Plugs.NeonAuthTest do
  use SupavisorWeb.ConnCase, async: false

  import Supavisor.TenantsFixtures

  alias SupavisorWeb.Plugs.NeonAuth

  @conn_str_ok "postgres://postgres.dev_tenant:postgres@localhost:6543/supavisor_test"

  defp build(conn_str, extras \\ []) do
    %{remote_ip: {127, 0, 0, 1}}
    |> then(fn base ->
      Enum.reduce(extras, base, fn {k, v}, acc -> Map.put(acc, k, v) end)
    end)
    |> then(fn base ->
      :get
      |> Phoenix.ConnTest.build_conn("/sql", "")
      |> Map.merge(base)
      |> Plug.Conn.put_req_header("neon-connection-string", conn_str)
    end)
  end

  defp enable_http_sql(enabled \\ true) do
    cfg = Application.get_env(:supavisor, :http_sql, [])
    Application.put_env(:supavisor, :http_sql, Keyword.put(cfg, :enabled, enabled))
    on_exit(fn -> Application.put_env(:supavisor, :http_sql, cfg) end)
  end

  defp enable_tenant_flag(flag \\ true) do
    tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")

    {:ok, _t} =
      Supavisor.Tenants.update_tenant(tenant, %{feature_flags: %{"http_sql" => flag}})
  end

  defp update_allow_list(allow_list) do
    tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")
    {:ok, _t} = Supavisor.Tenants.update_tenant(tenant, %{allow_list: allow_list})
  end

  describe "global feature flag" do
    test "returns 404 when :http_sql disabled" do
      enable_http_sql(false)
      conn = NeonAuth.call(build(@conn_str_ok), [])

      assert conn.halted
      assert conn.status == 404
      assert Jason.decode!(conn.resp_body)["code"] == "feature_disabled"
    end
  end

  describe "with global flag on, tenant flag off" do
    setup do
      _ = tenant_fixture()
      enable_http_sql(true)
      :ok
    end

    test "tenant_flag off → 404" do
      enable_tenant_flag(false)
      conn = NeonAuth.call(build(@conn_str_ok), [])
      assert conn.status == 404
      assert Jason.decode!(conn.resp_body)["code"] == "feature_disabled"
    end
  end

  describe "with global flag and tenant flag on" do
    setup do
      _ = tenant_fixture()
      enable_http_sql(true)
      enable_tenant_flag(true)
      :ok
    end

    test "happy path assigns http_sql_ctx" do
      conn = NeonAuth.call(build(@conn_str_ok), [])

      refute conn.halted
      ctx = conn.assigns.http_sql_ctx
      assert ctx.tenant_external_id == "dev_tenant"
      assert ctx.user == "postgres.dev_tenant"
      assert ctx.db_user == "postgres"
      assert ctx.password == "postgres"
      assert ctx.database == "supavisor_test"
      assert ctx.remote_ip == {127, 0, 0, 1}
    end

    test "missing header → 400" do
      conn =
        Phoenix.ConnTest.build_conn(:get, "/sql", "")
        |> NeonAuth.call([])

      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["code"] == "malformed_request"
    end

    test "malformed URL → 400" do
      conn = NeonAuth.call(build("not-a-url"), [])
      assert conn.status == 400
    end

    test "tenant not found → 401" do
      conn =
        NeonAuth.call(
          build("postgres://postgres.does_not_exist:postgres@localhost:6543/postgres"),
          []
        )

      assert conn.status == 401
    end

    test "respects x-forwarded-for header" do
      conn =
        build(@conn_str_ok)
        |> Plug.Conn.put_req_header("x-forwarded-for", "10.0.0.5, 172.16.0.1")
        |> NeonAuth.call([])

      refute conn.halted
      assert conn.assigns.http_sql_ctx.remote_ip == {10, 0, 0, 5}
    end

    test "Authorization: Bearer <jwt> → 401 (JWT unsupported in v1)" do
      conn =
        build(@conn_str_ok)
        |> Plug.Conn.put_req_header("authorization", "Bearer SOMEJWT")
        |> NeonAuth.call([])

      assert conn.status == 401
      assert Jason.decode!(conn.resp_body)["code"] == "unauthorized"
    end

    test "ip not in tenant allow_list → 403" do
      update_allow_list(["10.0.0.0/8"])

      conn = NeonAuth.call(build(@conn_str_ok), [])
      assert conn.status == 403
      assert Jason.decode!(conn.resp_body)["code"] == "ip_not_allowed"
    end
  end
end
