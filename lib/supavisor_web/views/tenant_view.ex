defmodule SupavisorWeb.TenantView do
  use SupavisorWeb, :view
  alias SupavisorWeb.TenantView

  def render("index.json", %{tenants: tenants}) do
    %{data: render_many(tenants, TenantView, "tenant.json")}
  end

  def render("show.json", %{tenant: tenant}) do
    %{data: render_one(tenant, TenantView, "tenant.json")}
  end

  def render("tenant.json", %{tenant: tenant}) do
    %{
      id: tenant.id,
      external_id: tenant.external_id,
      db_host: tenant.db_host,
      db_port: tenant.db_port,
      db_user: tenant.db_user,
      db_database: tenant.db_database,
      pool_size: tenant.pool_size
    }
  end
end
