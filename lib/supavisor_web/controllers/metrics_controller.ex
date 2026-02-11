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
    tune_index_proc()

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

  # we know, we're about to process large amount of data, so to skip some of
  # heap growth ceremony we set the min_heap_size to ~100mb (see runtime.exs)
  #
  # to keep memory usage at bay, we disable generational GC by setting fullsweep_after to 0
  # (see runtime.exs); that could become less conservative with values like 2, 10 or 20
  # speeding up memory reclamation, but since we see LARGE (even GBs) of data being
  # processes here, we trade memory consumption at the expense of CPU - like we'll
  # be more busy doing large GCs, but we'll maintain lower `total_heap_size`
  defp tune_index_proc() do
    with mhs when is_integer(mhs) and mhs > 0 <-
           Application.get_env(:supavisor, __MODULE__)[:index_min_heap_size_mb] do
      :erlang.process_flag(:min_heap_size, Helpers.mb_to_words(mhs))
    end

    with fsa when is_integer(fsa) and fsa >= 0 <-
           Application.get_env(:supavisor, __MODULE__)[:index_fullsweep_after] do
      :erlang.process_flag(:fullsweep_after, fsa)
    end
  end
end
