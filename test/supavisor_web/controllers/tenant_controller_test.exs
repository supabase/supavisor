defmodule SupavisorWeb.TenantControllerTest do
  use SupavisorWeb.ConnCase

  import Supavisor.TenantsFixtures

  alias Supavisor.Tenants.Tenant

  @jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.M9jrxyvPLkUxWgOYSf5dNdJ8v_eRrq810ShFRT8N-6M"

  @create_attrs %{
    db_database: "some db_database",
    db_host: "some db_host",
    db_password: "some db_password",
    db_port: 42,
    db_user: "some db_user",
    external_id: "dev_tenant",
    pool_size: 42
  }
  @update_attrs %{
    db_database: "some updated db_database",
    db_host: "some updated db_host",
    db_password: "some updated db_password",
    db_port: 43,
    db_user: "some updated db_user",
    external_id: "dev_tenant",
    pool_size: 43
  }
  @invalid_attrs %{
    db_database: nil,
    db_host: nil,
    db_password: nil,
    db_port: nil,
    db_user: nil,
    external_id: nil,
    pool_size: nil
  }

  setup %{conn: conn} do
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
      conn = put(conn, Routes.tenant_path(conn, :update, external_id), tenant: @update_attrs)
      assert %{"external_id" => ^external_id} = json_response(conn, 200)["data"]

      conn = get(conn, Routes.tenant_path(conn, :show, external_id))

      assert %{
               "external_id" => ^external_id,
               "db_database" => "some updated db_database",
               "db_host" => "some updated db_host",
               "db_port" => 43,
               "db_user" => "some updated db_user",
               "pool_size" => 43
             } = json_response(conn, 200)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn, tenant: tenant} do
      conn = put(conn, Routes.tenant_path(conn, :update, tenant), tenant: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "delete tenant" do
    setup [:create_tenant]

    test "deletes chosen tenant", %{conn: conn, tenant: %Tenant{external_id: external_id}} do
      conn = delete(conn, Routes.tenant_path(conn, :delete, external_id))
      assert response(conn, 204)
    end
  end

  defp create_tenant(_) do
    tenant = tenant_fixture()
    %{tenant: tenant}
  end
end
