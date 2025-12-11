defmodule Supavisor.Monitoring.Peepers2 do
  @moduledoc """
  Rust-based metrics aggregation and export for Peep metrics.

  This module provides a complete Rust-based pipeline for metrics processing:
  1. Preprocess ETS data in Elixir (extract atomics values for distributions)
  2. Aggregate and export metrics in a single Rust NIF call

  This approach is significantly faster than the Elixir-based aggregation
  and avoids converting tags to strings during aggregation (only during export).
  """

  use Rustler, otp_app: :supavisor, crate: "peepers2"

  alias Peep.Storage
  alias Telemetry.Metrics

  @doc """
  Aggregate and export preprocessed metrics to Prometheus format.

  Takes a list of preprocessed metrics (from preprocess_metrics/2) and the itm map,
  aggregates them in Rust, and returns a string in Prometheus exposition format.

  This is a single NIF call that performs both aggregation and export for maximum
  performance. Tags are stored as terms during aggregation and only converted to
  strings once during export.
  """
  def aggregate_and_export(_preprocessed_data, _itm_map), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Get all metrics from Peep storage and export to Prometheus format.

  This is the main entry point that combines preprocessing, aggregation, and export.
  """
  def get_metrics(name) do
    case Peep.Persistent.fetch(name) do
      %Peep.Persistent{storage: {_storage_mod, storage}, ids_to_metrics: itm} ->
        preprocessed = preprocess_metrics(storage, itm)
        aggregate_and_export(preprocessed, itm)

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
