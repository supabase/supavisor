defmodule Supavisor.Monitoring.Peepers2 do
  @moduledoc """
  Rust-based metrics aggregation and export for Peep metrics.

  This module provides a complete Rust-based pipeline for metrics processing:
  1. Preprocess ETS data in Elixir (extract atomics values for distributions)
  2. Aggregate metrics in Rust using a resource
  3. Export directly from the Rust resource to Prometheus format

  This approach is significantly faster than the Elixir-based aggregation.
  """

  use Rustler, otp_app: :supavisor, crate: "peepers2"

  alias Peep.Storage
  alias Telemetry.Metrics

  @doc """
  Aggregate preprocessed metrics into a Rust resource.

  Takes a list of preprocessed metrics (from preprocess_metrics/2) and the itm map,
  returns a Rust resource containing the aggregated data.
  """
  def aggregate_metrics(_preprocessed_data, _itm_map), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Export aggregated metrics to Prometheus text format.

  Takes the aggregated metrics resource and returns a binary string
  in Prometheus exposition format.
  """
  def export_aggregated_metrics(_aggregated_resource), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Get all metrics from Peep storage and export to Prometheus format.

  This is the main entry point that combines preprocessing, aggregation, and export.
  """
  def get_metrics(name) do
    case Peep.Persistent.fetch(name) do
      %Peep.Persistent{storage: {_storage_mod, storage}, ids_to_metrics: itm} = p ->
        preprocessed = preprocess_metrics(storage, itm)

        aggregate_metrics(preprocessed, itm)
        |> export_aggregated_metrics()

      _ ->
        ""
    end
  end

  @doc """
  Preprocess ETS metrics data for Rust aggregation.

  This function:
  1. Reads all ETS tables using tab2list
  2. Extracts values from Storage.Atomics for distributions
  3. Removes timestamps from last values
  4. Returns a list of {metric_type, metric_id, tags, value} tuples (metric_id instead of full struct)
  """
  def preprocess_metrics(tids, itm) when is_tuple(tids) do
    tids
    |> Tuple.to_list()
    |> Enum.flat_map(&preprocess_table(&1, itm))
  end

  defp preprocess_table(tid, itm) do
    :ets.tab2list(tid)
    |> Enum.map(&preprocess_metric(&1, itm))
  end

  defp preprocess_metric({{id, tags}, value}, itm) do
    case itm do
      %{^id => metric} ->
        preprocess_metric_with_type(metric, id, tags, value)
    end
  end

  defp preprocess_metric_with_type(%Metrics.Counter{}, id, tags, value) do
    {:counter, id, tags, value}
  end

  defp preprocess_metric_with_type(%Metrics.Sum{}, id, tags, value) do
    {:sum, id, tags, value}
  end

  defp preprocess_metric_with_type(%Metrics.LastValue{}, id, tags, {_timestamp, value}) do
    {:last_value, id, tags, value}
  end

  # Distribution: extract values from Storage.Atomics
  defp preprocess_metric_with_type(
         %Metrics.Distribution{},
         id,
         tags,
         %Storage.Atomics{} = atomics
       ) do
    values = Storage.Atomics.values(atomics)
    {:distribution, id, tags, values}
  end
end
