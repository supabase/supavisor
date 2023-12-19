defmodule SupavisorWeb.TenantView do
  use SupavisorWeb, :view
  alias SupavisorWeb.TenantView
  alias SupavisorWeb.UserView

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
      db_database: tenant.db_database,
      ip_version: tenant.ip_version,
      upstream_ssl: tenant.upstream_ssl,
      upstream_verify: tenant.upstream_verify,
      enforce_ssl: tenant.enforce_ssl,
      require_user: tenant.require_user,
      auth_query: tenant.auth_query,
      sni_hostname: tenant.sni_hostname,
      default_pool_size: tenant.default_pool_size,
      default_max_clients: tenant.default_max_clients,
      client_idle_timeout: tenant.client_idle_timeout,
      default_pool_strategy: tenant.default_pool_strategy,
      users: render_many(tenant.users, UserView, "user.json")
    }
  end

  def render("error.json", %{error: reason}) do
    %{error: reason}
  end

  def render("show_terminate.json", %{result: result}) do
    %{result: result}
  end

  def render("not_found.json", _) do
    %{error: "not found"}
  end
end
