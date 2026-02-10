defmodule SupavisorWeb.MetricsController do
  @moduledoc """
  Handles requests for Prometheus metrics
  from all nodes in the cluster.
  """

  use SupavisorWeb, :controller
  require Logger
  alias Supavisor.Monitoring.PromEx
  alias Supavisor.Helpers

  @spec index(Plug.Conn.t(), any()) :: Plug.Conn.t()
  def index(conn, _) do
    :proc_lib.set_label(:metrics_handler)

    :erlang.process_flag(
      :min_heap_size,
      Helpers.mb_to_words(Application.get_env(:supavisor, __MODULE__)[:index_min_heap_size_mb])
    )

    cluster_metrics = PromEx.get_cluster_metrics()

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, cluster_metrics)
  end

  def tenant(conn, %{"external_id" => ext_id}) do
    :proc_lib.set_label({:tenant_metrics_handler, ext_id})

    cluster_metrics = PromEx.get_cluster_tenant_metrics(ext_id)

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, [cluster_metrics, "\n"])
  end
end
