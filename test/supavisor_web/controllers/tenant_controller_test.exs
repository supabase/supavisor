defmodule SupavisorWeb.TenantControllerTest do
  use SupavisorWeb.ConnCase

  import Supavisor.TenantsFixtures
  import ExUnit.CaptureLog
  require Logger
  alias Supavisor.Tenants.Tenant

  @jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.M9jrxyvPLkUxWgOYSf5dNdJ8v_eRrq810ShFRT8N-6M"

  @user_valid_attrs %{
    db_user_alias: "some_db_user",
    db_user: "some db_user",
    db_password: "some db_password",
    pool_size: 3,
    mode_type: "transaction"
  }

  @create_attrs %{
    db_database: "some db_database",
    db_host: "some db_host",
    db_port: 42,
    external_id: "dev_tenant",
    require_user: true,
    users: [@user_valid_attrs]
  }
  @update_attrs %{
    db_database: "some updated db_database",
    db_host: "some updated db_host",
    db_port: 43,
    external_id: "dev_tenant",
    require_user: true,
    allow_list: ["71.209.249.38/32"],
    users: [@user_valid_attrs]
  }
  @invalid_attrs %{
    db_database: nil,
    db_host: nil,
    db_port: nil,
    external_id: nil
  }

  setup %{conn: conn} do
    :meck.expect(Supavisor.Helpers, :check_creds_get_ver, fn _ -> {:ok, "0.0"} end)

    new_conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header(
        "authorization",
        "Bearer " <> @jwt
      )

    {:ok, conn: new_conn}
  end

  describe "create tenant" do
    test "renders tenant when data is valid", %{conn: conn} do
      conn = put(conn, Routes.tenant_path(conn, :update, "dev_tenant"), tenant: @create_attrs)
      assert %{"external_id" => _id} = json_response(conn, 201)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn} do
      conn = put(conn, Routes.tenant_path(conn, :update, "dev_tenant"), tenant: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "update tenant" do
    setup [:create_tenant]

    test "renders tenant when data is valid", %{
      conn: conn,
      tenant: %Tenant{external_id: external_id} = _tenant
    } do
      set_cache(external_id)
      conn = put(conn, Routes.tenant_path(conn, :update, external_id), tenant: @update_attrs)
      assert %{"external_id" => ^external_id} = json_response(conn, 200)["data"]
      check_cache(external_id)

      conn = get(conn, Routes.tenant_path(conn, :show, external_id))

      assert %{
               "external_id" => ^external_id,
               "db_database" => "some updated db_database",
               "db_host" => "some updated db_host",
               "db_port" => 43,
               "allow_list" => ["71.209.249.38/32"]
             } = json_response(conn, 200)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn, tenant: tenant} do
      conn = put(conn, Routes.tenant_path(conn, :update, tenant), tenant: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end

    test "triggers Supavisor.stop/2", %{
      conn: conn,
      tenant: %Tenant{external_id: external_id}
    } do
      msg = "Stop #{@update_attrs.external_id}"

      assert capture_log(fn ->
               put(conn, Routes.tenant_path(conn, :update, external_id), tenant: @update_attrs)
             end) =~ msg
    end
  end

  describe "delete tenant" do
    setup [:create_tenant]

    test "deletes chosen tenant", %{conn: conn, tenant: %Tenant{external_id: external_id}} do
      set_cache(external_id)
      conn = delete(conn, Routes.tenant_path(conn, :delete, external_id))
      check_cache(external_id)
      assert response(conn, 204)
    end
  end

  describe "get tenant" do
    setup [:create_tenant]

    test "returns 404 not found for non-existing tenant", %{conn: conn} do
      non_existing_tenant_id = "non_existing_tenant_id"

      conn = get(conn, Routes.tenant_path(conn, :show, non_existing_tenant_id))
      assert json_response(conn, 404)["error"] == "not found"
    end
  end

  defp create_tenant(_) do
    tenant = tenant_fixture()
    %{tenant: tenant}
  end

  defp set_cache(external_id) do
    Supavisor.Tenants.get_user_cache(:single, "user", external_id, nil)
    Supavisor.Tenants.get_tenant_cache(external_id, nil)
  end

  defp check_cache(external_id) do
    assert {:ok, nil} =
             Cachex.get(Supavisor.Cache, {:user_cache, :single, "user", external_id, nil})

    assert {:ok, nil} = Cachex.get(Supavisor.Cache, {:tenant_cache, external_id, nil})
  end
end
