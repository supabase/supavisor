defmodule Supavisor.Monitoring.PeepFoldl do
  @moduledoc """
  Alternative version of Peep metric collection using :ets.foldl instead of tab2list.

  This module provides a drop-in replacement for Peep.Storage.Striped.get_all_metrics/2
  that avoids copying all ETS data to a list, instead processing it in-place using foldl.
  """

  alias Telemetry.Metrics
  alias Peep.Storage

  @doc """
  Get all metrics from striped storage using optimized :ets.foldl approach.

  This is a drop-in replacement for Peep.Storage.Striped.get_all_metrics/2.
  """
  def get_all_metrics(tids, %Peep.Persistent{ids_to_metrics: itm}) do
    acc = get_all_metrics_foldl(Tuple.to_list(tids), itm, %{})
    remove_timestamps_from_last_values(acc)
  end

  defp get_all_metrics_foldl([], _itm, acc), do: acc

  defp get_all_metrics_foldl([tid | rest], itm, acc) do
    # Use :ets.foldl to process table in-place without copying to list
    acc = :ets.foldl(
      fn metric, acc_inner ->
        add_metric(metric, itm, acc_inner)
      end,
      acc,
      tid
    )
    get_all_metrics_foldl(rest, itm, acc)
  end

  defp add_metric({{id, _tags}, _value} = kv, itm, acc) do
    case itm do
      %{^id => metric} ->
        add_metric2(kv, metric, acc)
      _ ->
        acc
    end
  end

  defp add_metric2({{_id, tags}, value}, %Metrics.Counter{} = metric, acc) do
    path = [Access.key(metric, %{}), Access.key(tags, 0)]
    update_in(acc, path, &(&1 + value))
  end

  defp add_metric2({{_id, tags}, value}, %Metrics.Sum{} = metric, acc) do
    path = [Access.key(metric, %{}), Access.key(tags, 0)]
    update_in(acc, path, &(&1 + value))
  end

  defp add_metric2({{_id, tags}, {_, _} = a}, %Metrics.LastValue{} = metric, acc) do
    path = [
      Access.key(:last_values, %{}),
      Access.key(metric, %{}),
      Access.key(tags, a)
    ]

    update_in(acc, path, fn {_, _} = b -> max(a, b) end)
  end

  defp add_metric2({{_id, tags}, atomics}, %Metrics.Distribution{} = metric, acc) do
    path = [
      Access.key(metric, %{}),
      Access.key(tags, %{})
    ]

    values = Storage.Atomics.values(atomics)

    update_in(acc, path, fn m1 -> Map.merge(m1, values, fn _k, v1, v2 -> v1 + v2 end) end)
  end

  defp remove_timestamps_from_last_values(%{last_values: lvs} = metrics) do
    last_value_metrics =
      for {metric, tags_to_values} <- lvs,
          {tags, {_ts, value}} <- tags_to_values,
          reduce: %{} do
        acc ->
          put_in(acc, [Access.key(metric, %{}), Access.key(tags)], value)
      end

    metrics
    |> Map.delete(:last_values)
    |> Map.merge(last_value_metrics)
  end

  defp remove_timestamps_from_last_values(metrics), do: metrics

  @doc """
  Wrapper function to fetch metrics using the foldl approach.

  Usage:
    Supavisor.Monitoring.PeepFoldl.get_all_metrics(:prom_ex_peep)
  """
  def get_all_metrics(name) do
    case Peep.Persistent.fetch(name) do
      %Peep.Persistent{storage: {_storage_mod, storage}} = p ->
        # Use our optimized version instead of calling storage_mod.get_all_metrics
        get_all_metrics(storage, p)

      _ ->
        nil
    end
  end
end
