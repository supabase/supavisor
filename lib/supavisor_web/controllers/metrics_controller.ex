defmodule SupavisorWeb.MetricsController do
  @moduledoc """
  Handles requests for Prometheus metrics
  from all nodes in the cluster.
  """

  use SupavisorWeb, :controller
  require Logger
  alias Supavisor.Monitoring.PromEx

  @spec index(Plug.Conn.t(), any()) :: Plug.Conn.t()
  def index(conn, _) do
    cluster_metrics = PromEx.get_cluster_metrics()

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, cluster_metrics)
  end

  def tenant(conn, %{"external_id" => ext_id}) do
    cluster_metrics = PromEx.get_cluster_tenant_metrics(ext_id)
    code = if cluster_metrics == [], do: 404, else: 200

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(code, [cluster_metrics, "\n"])
  end
end
