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
    cluster_metrics = fetch_cluster_metrics()

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, cluster_metrics)
  end

  @spec fetch_cluster_metrics() :: String.t()
  def fetch_cluster_metrics() do
    Node.list()
    |> Task.async_stream(&fetch_node_metrics/1, timeout: :infinity)
    |> Enum.reduce(PromEx.get_metrics(), &merge_node_metrics/2)
  end

  @spec fetch_node_metrics(atom()) :: {atom(), term()}
  defp fetch_node_metrics(node) do
    {node, :rpc.call(node, PromEx, :get_metrics, [], 10_000)}
  end

  defp merge_node_metrics({_, {node, {:badrpc, reason}}}, acc) do
    Logger.error("Cannot fetch metrics from the node #{inspect(node)} because #{inspect(reason)}")
    acc
  end

  defp merge_node_metrics({_, {_node, metrics}}, acc) do
    acc <> metrics
  end
end
