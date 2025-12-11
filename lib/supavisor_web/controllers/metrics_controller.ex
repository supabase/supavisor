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
    conn =
      conn
      |> put_resp_content_type("text/plain")
      |> send_chunked(200)

    PromEx.stream_metrics()
    |> Enum.reduce_while(conn, fn chunk, conn ->
      case chunk(conn, chunk) do
        {:ok, conn} -> {:cont, conn}
        {:error, :closed} -> {:halt, conn}
      end
    end)
  end

  def tenant(conn, %{"external_id" => ext_id}) do
    cluster_metrics = PromEx.get_cluster_tenant_metrics(ext_id)

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, [cluster_metrics, "\n"])
  end
end
