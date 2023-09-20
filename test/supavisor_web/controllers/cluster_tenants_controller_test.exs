defmodule SupavisorWeb.ClusterTenantsControllerTest do
  use SupavisorWeb.ConnCase

  import Supavisor.TenantsFixtures

  alias Supavisor.Tenants.ClusterTenants

  @create_attrs %{
    active: true
  }
  @update_attrs %{
    active: false
  }
  @invalid_attrs %{active: nil}

  setup %{conn: conn} do
    {:ok, conn: put_req_header(conn, "accept", "application/json")}
  end

  describe "index" do
    test "lists all cluster_tenants", %{conn: conn} do
      conn = get(conn, ~p"/api/cluster_tenants")
      assert json_response(conn, 200)["data"] == []
    end
  end

  describe "create cluster_tenants" do
    test "renders cluster_tenants when data is valid", %{conn: conn} do
      conn = post(conn, ~p"/api/cluster_tenants", cluster_tenants: @create_attrs)
      assert %{"id" => id} = json_response(conn, 201)["data"]

      conn = get(conn, ~p"/api/cluster_tenants/#{id}")

      assert %{
               "id" => ^id,
               "active" => true
             } = json_response(conn, 200)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn} do
      conn = post(conn, ~p"/api/cluster_tenants", cluster_tenants: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "update cluster_tenants" do
    setup [:create_cluster_tenants]

    test "renders cluster_tenants when data is valid", %{conn: conn, cluster_tenants: %ClusterTenants{id: id} = cluster_tenants} do
      conn = put(conn, ~p"/api/cluster_tenants/#{cluster_tenants}", cluster_tenants: @update_attrs)
      assert %{"id" => ^id} = json_response(conn, 200)["data"]

      conn = get(conn, ~p"/api/cluster_tenants/#{id}")

      assert %{
               "id" => ^id,
               "active" => false
             } = json_response(conn, 200)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn, cluster_tenants: cluster_tenants} do
      conn = put(conn, ~p"/api/cluster_tenants/#{cluster_tenants}", cluster_tenants: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "delete cluster_tenants" do
    setup [:create_cluster_tenants]

    test "deletes chosen cluster_tenants", %{conn: conn, cluster_tenants: cluster_tenants} do
      conn = delete(conn, ~p"/api/cluster_tenants/#{cluster_tenants}")
      assert response(conn, 204)

      assert_error_sent 404, fn ->
        get(conn, ~p"/api/cluster_tenants/#{cluster_tenants}")
      end
    end
  end

  defp create_cluster_tenants(_) do
    cluster_tenants = cluster_tenants_fixture()
    %{cluster_tenants: cluster_tenants}
  end
end
