defmodule SupavisorWeb.ClusterView do
  use SupavisorWeb, :view
  alias SupavisorWeb.ClusterView
  alias SupavisorWeb.UserView

  def render("index.json", %{clusters: clusters}) do
    %{data: render_many(clusters, ClusterView, "cluster.json")}
  end

  def render("show.json", %{cluster: cluster}) do
    %{data: render_one(cluster, ClusterView, "cluster.json")}
  end

  def render("cluster.json", %{cluster: cluster}) do
    %{
      id: cluster.id
      # external_id: tenant.external_id,
      # db_host: tenant.db_host,
      # db_port: tenant.db_port,
      # db_database: tenant.db_database,
      # ip_version: tenant.ip_version,
      # upstream_ssl: tenant.upstream_ssl,
      # upstream_verify: tenant.upstream_verify,
      # enforce_ssl: tenant.enforce_ssl,
      # require_user: tenant.require_user,
      # auth_query: tenant.auth_query,
      # sni_hostname: tenant.sni_hostname,
      # default_max_clients: tenant.default_max_clients,
      # users: render_many(tenant.users, UserView, "user.json")
    }
  end

  def render("error.json", %{error: reason}) do
    %{error: reason}
  end

  def render("show_terminate.json", %{result: result}) do
    %{result: result}
  end
end
