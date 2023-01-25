defmodule PgEdgeWeb.TenantControllerTest do
  use PgEdgeWeb.ConnCase

  import PgEdge.TenantsFixtures

  alias PgEdge.Tenants.Tenant

  @create_attrs %{
    db_database: "some db_database",
    db_host: "some db_host",
    db_password: "some db_password",
    db_port: 42,
    db_user: "some db_user",
    external_id: "some external_id",
    pool_size: 42
  }
  @update_attrs %{
    db_database: "some updated db_database",
    db_host: "some updated db_host",
    db_password: "some updated db_password",
    db_port: 43,
    db_user: "some updated db_user",
    external_id: "some updated external_id",
    pool_size: 43
  }
  @invalid_attrs %{db_database: nil, db_host: nil, db_password: nil, db_port: nil, db_user: nil, external_id: nil, pool_size: nil}

  setup %{conn: conn} do
    {:ok, conn: put_req_header(conn, "accept", "application/json")}
  end

  describe "index" do
    test "lists all tenants", %{conn: conn} do
      conn = get(conn, Routes.tenant_path(conn, :index))
      assert json_response(conn, 200)["data"] == []
    end
  end

  describe "create tenant" do
    test "renders tenant when data is valid", %{conn: conn} do
      conn = post(conn, Routes.tenant_path(conn, :create), tenant: @create_attrs)
      assert %{"id" => id} = json_response(conn, 201)["data"]

      conn = get(conn, Routes.tenant_path(conn, :show, id))

      assert %{
               "id" => ^id,
               "db_database" => "some db_database",
               "db_host" => "some db_host",
               "db_password" => "some db_password",
               "db_port" => 42,
               "db_user" => "some db_user",
               "external_id" => "some external_id",
               "pool_size" => 42
             } = json_response(conn, 200)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn} do
      conn = post(conn, Routes.tenant_path(conn, :create), tenant: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "update tenant" do
    setup [:create_tenant]

    test "renders tenant when data is valid", %{conn: conn, tenant: %Tenant{id: id} = tenant} do
      conn = put(conn, Routes.tenant_path(conn, :update, tenant), tenant: @update_attrs)
      assert %{"id" => ^id} = json_response(conn, 200)["data"]

      conn = get(conn, Routes.tenant_path(conn, :show, id))

      assert %{
               "id" => ^id,
               "db_database" => "some updated db_database",
               "db_host" => "some updated db_host",
               "db_password" => "some updated db_password",
               "db_port" => 43,
               "db_user" => "some updated db_user",
               "external_id" => "some updated external_id",
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

    test "deletes chosen tenant", %{conn: conn, tenant: tenant} do
      conn = delete(conn, Routes.tenant_path(conn, :delete, tenant))
      assert response(conn, 204)

      assert_error_sent 404, fn ->
        get(conn, Routes.tenant_path(conn, :show, tenant))
      end
    end
  end

  defp create_tenant(_) do
    tenant = tenant_fixture()
    %{tenant: tenant}
  end
end
