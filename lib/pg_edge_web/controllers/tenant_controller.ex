defmodule PgEdgeWeb.TenantController do
  use PgEdgeWeb, :controller

  alias PgEdge.Tenants
  alias PgEdge.Tenants.Tenant

  action_fallback PgEdgeWeb.FallbackController

  def index(conn, _params) do
    tenants = Tenants.list_tenants()
    render(conn, "index.json", tenants: tenants)
  end

  def create(conn, %{"tenant" => tenant_params}) do
    with {:ok, %Tenant{} = tenant} <- Tenants.create_tenant(tenant_params) do
      conn
      |> put_status(:created)
      |> put_resp_header("location", Routes.tenant_path(conn, :show, tenant))
      |> render("show.json", tenant: tenant)
    end
  end

  def show(conn, %{"id" => id}) do
    id
    |> Tenants.get_tenant_by_external_id()
    |> case do
      %Tenant{} = tenant ->
        render(conn, "show.json", tenant: tenant)

      nil ->
        conn
        |> put_status(404)
        |> render("not_found.json", tenant: nil)
    end
  end

  def update(conn, %{"id" => id, "tenant" => tenant_params}) do
    case Tenants.get_tenant_by_external_id(id) do
      nil ->
        create(conn, %{"tenant" => Map.put(tenant_params, "external_id", id)})

      tenant ->
        with {:ok, %Tenant{} = tenant} <- Tenants.update_tenant(tenant, tenant_params) do
          render(conn, "show.json", tenant: tenant)
        end
    end
  end

  def delete(conn, %{"id" => id}) do
    if Tenants.delete_tenant_by_external_id(id) do
      send_resp(conn, 204, "")
    else
      send_resp(conn, 404, "")
    end
  end
end
