defmodule Supavisor.Monitoring.StreamingMetrics do
  @moduledoc """
  Streaming metrics exporter that processes one metric at a time to reduce memory pressure.

  Instead of loading all metrics into memory at once, this module:
  1. Iterates through each metric in the `ids_to_metrics` map
  2. Fetches only that metric's data from all striped tables
  3. Aggregates and exports it immediately
  4. Yields the chunk to allow GC before processing the next metric

  This reduces peak memory from O(all_metrics) to O(largest_single_metric).

  Uses Rust NIFs from Supavisor.Monitoring.Peepers for fast string escaping.
  """

  alias Peep.Storage
  alias Supavisor.Monitoring.Peepers
  alias Telemetry.Metrics

  @doc """
  Returns a Stream that yields Prometheus-formatted chunks for all metrics.

  Usage:
      stream_metrics(:my_peep_collector)
      |> Enum.to_list()
      |> IO.iodata_to_binary()
  """
  @spec stream_metrics(atom()) :: Enumerable.t()
  def stream_metrics(collector_name) do
    %Peep.Persistent{storage: {_, tids}, ids_to_metrics: itm} =
      Peep.Persistent.fetch(collector_name)

    table_list = Tuple.to_list(tids)

    # Stream through each metric ID in the itm map
    Stream.concat([
      itm
      |> Stream.map(fn {metric_id, metric_spec} ->
        aggregate_and_format_metric(metric_id, metric_spec, table_list, itm)
      end),
      # Add EOF marker at the end
      Stream.map(["# EOF\n"], & &1)
    ])
  end

  @doc """
  Aggregates a single metric from all striped tables and formats it.
  """
  defp aggregate_and_format_metric(metric_id, metric_spec, table_list, itm) do
    # Collect all entries for this metric_id from all tables
    entries = collect_metric_entries(metric_id, table_list)

    # Aggregate the entries into a single metric map
    aggregated = aggregate_entries(entries, metric_id, itm)

    # Format to Prometheus text
    case aggregated do
      %{^metric_spec => series} when map_size(series) > 0 ->
        format_metric({metric_spec, series})

      _ ->
        # Metric has no data, skip it
        ""
    end
  end

  @doc """
  Collects all entries for a specific metric_id from all striped tables.
  """
  defp collect_metric_entries(metric_id, table_list) do
    Enum.flat_map(table_list, fn tid ->
      # Match spec: select all entries where the key starts with {metric_id, ...}
      # Returns the full entry: {{metric_id, tags}, value}
      match_spec = [
        {{{metric_id, :"$1"}, :"$2"}, [], [{{:"$1", :"$2"}}]}
      ]

      :ets.select(tid, match_spec)
    end)
  end

  @doc """
  Aggregates entries for a single metric into the standard Peep format.
  """
  defp aggregate_entries(entries, metric_id, itm) do
    %{^metric_id => metric_spec} = itm

    Enum.reduce(entries, %{}, fn {tags, value}, acc ->
      add_entry(acc, metric_spec, tags, value)
    end)
  end

  # Counter: sum values across all tables
  defp add_entry(acc, %Metrics.Counter{} = metric, tags, value) do
    path = [Access.key(metric, %{}), Access.key(tags, 0)]
    update_in(acc, path, &(&1 + value))
  end

  # Sum: sum values across all tables
  defp add_entry(acc, %Metrics.Sum{} = metric, tags, value) do
    path = [Access.key(metric, %{}), Access.key(tags, 0)]
    update_in(acc, path, &(&1 + value))
  end

  # LastValue: keep the most recent value (max timestamp)
  defp add_entry(acc, %Metrics.LastValue{} = metric, tags, {_timestamp, _value} = timestamped) do
    path = [Access.key(metric, %{}), Access.key(tags, timestamped)]
    update_in(acc, path, fn existing -> max(existing, timestamped) end)
  end

  # Distribution: merge bucket counts
  defp add_entry(acc, %Metrics.Distribution{} = metric, tags, %Storage.Atomics{} = atomics) do
    path = [Access.key(metric, %{}), Access.key(tags, %{})]
    values = Storage.Atomics.values(atomics)

    update_in(acc, path, fn existing ->
      Map.merge(existing, values, fn _k, v1, v2 -> v1 + v2 end)
    end)
  end

  ## Formatting functions (adapted from Peep.Prometheus)

  defp format_metric({%Metrics.Counter{}, _series} = metric) do
    format_standard(metric, "counter")
  end

  defp format_metric({%Metrics.Sum{} = spec, _series} = metric) do
    format_standard(metric, spec.reporter_options[:prometheus_type] || "counter")
  end

  defp format_metric({%Metrics.LastValue{} = spec, series} = metric) do
    # Remove timestamps from LastValue series
    series_without_timestamps =
      for {tags, {_ts, value}} <- series, into: %{}, do: {tags, value}

    format_standard({spec, series_without_timestamps}, spec.reporter_options[:prometheus_type] || "gauge")
  end

  defp format_metric({%Metrics.Distribution{} = metric, tagged_series}) do
    name = format_name(metric.name)
    help = ["# HELP ", name, " ", escape_help(metric.description)]
    type = ["# TYPE ", name, " histogram"]

    distributions =
      Enum.map(tagged_series, fn {tags, buckets} ->
        format_distribution(name, tags, buckets)
      end)

    [help, ?\n, type, ?\n, distributions]
  end

  defp format_standard({metric, series}, type) do
    name = format_name(metric.name)
    help = ["# HELP ", name, " ", escape_help(metric.description)]
    type_line = ["# TYPE ", name, " ", type]

    samples =
      Enum.map(series, fn
        {tags, value} when is_integer(value) ->
          if Enum.empty?(tags) do
            [name, " ", Integer.to_string(value), ?\n]
          else
            [name, ?{, format_labels(tags), "} ", Integer.to_string(value), ?\n]
          end

        {tags, value} when is_float(value) ->
          if Enum.empty?(tags) do
            [name, " ", format_value(value), ?\n]
          else
            [name, ?{, format_labels(tags), "} ", format_value(value), ?\n]
          end
      end)

    [help, ?\n, type_line, ?\n, samples]
  end

  defp format_distribution(name, tags, buckets) do
    has_labels? = not Enum.empty?(tags)

    buckets_as_floats =
      Map.drop(buckets, [:sum, :infinity])
      |> Enum.map(fn {bucket_string, count} -> {String.to_float(bucket_string), count} end)
      |> Enum.sort()

    {prefix_sums, count} = prefix_sums(buckets_as_floats)

    {labels_done, bucket_partial} =
      if has_labels? do
        labels = format_labels(tags)
        {[?{, labels, "} "], [name, "_bucket{", labels, ",le=\""]}
      else
        {?\s, [name, "_bucket{le=\""]}
      end

    samples =
      prefix_sums
      |> Enum.sort()
      |> Enum.map(fn {upper_bound, count} ->
        [bucket_partial, format_value(upper_bound), "\"} ", Integer.to_string(count), ?\n]
      end)

    sum = Map.get(buckets, :sum, 0)
    inf = Map.get(buckets, :infinity, 0)

    [
      samples,
      [bucket_partial, "+Inf\"} ", Integer.to_string(count + inf), ?\n],
      [name, "_sum", labels_done, Integer.to_string(sum), ?\n],
      [name, "_count", labels_done, Integer.to_string(count + inf), ?\n]
    ]
  end

  defp prefix_sums(buckets_as_floats) do
    {prefix_sums, count} =
      Enum.map_reduce(buckets_as_floats, 0, fn {upper_bound, count}, sum ->
        {{upper_bound, sum + count}, sum + count}
      end)

    {prefix_sums, count}
  end

  defp format_name(name) when is_list(name) do
    name
    |> Enum.map(&Atom.to_string/1)
    |> Enum.join("_")
  end

  defp format_labels(tags) do
    tags
    |> Enum.map(fn {k, v} -> [Atom.to_string(k), "=\"", escape_label(v), "\""] end)
    |> Enum.intersperse(?,)
  end

  defp escape_label(value) when is_binary(value) do
    Peepers.escape_label(value)
  end

  defp escape_label(value), do: Peepers.escape_label(to_string(value))

  defp escape_help(nil), do: ""

  defp escape_help(description) do
    Peepers.escape_help(description)
  end

  defp format_value(value) when is_float(value) do
    case Float.ratio(value) do
      {0, _} -> "0.0"
      {_num, 0} -> raise "division by zero"
      _ -> Float.to_string(value)
    end
  end

  defp format_value(value) when is_integer(value) do
    Integer.to_string(value)
  end
end
