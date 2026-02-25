defmodule Supavisor.Monitoring.PromEx do
  @moduledoc """
  This module configures the PromEx application for Supavisor. It defines
  the plugins used for collecting metrics, including built-in plugins and custom ones,
  and provides a function to remove remote metrics associated with a specific tenant.
  """

  use PromEx, otp_app: :supavisor
  require Logger

  alias PromEx.Plugins
  alias Supavisor.PeepStorage
  alias Supavisor.PeepStorage.PrometheusCached
  alias Supavisor.PromEx.Plugins.{Cluster, OsMon, Tenant}
  alias Telemetry.Metrics

  defmodule Store do
    @moduledoc """
    Storage module for PromEx that provide additional functionality of using
    global tags (extracted from Logger global metadata). It also disables
    scraping using `PromEx.scrape/1` function as it should not be used directly.
    We expose scraping via `Supavisor.Monitoring.PromEx.get_metrics/0` function.
    """

    @behaviour PromEx.Storage

    @impl true
    def scrape(_name) do
      # Hack to not report errors from ETSCronFlusher
      if match?({PromEx.ETSCronFlusher, _, _}, Process.get(:"$initial_call")) do
        ""
      else
        raise(
          "Do not use PromEx.scrape/1, instead use Supavisor.Monitoring.PromEx.fetch_cluster_metrics/0"
        )
      end
    end

    @impl true
    def child_spec(name, metrics) do
      global_tags = :logger.get_primary_config().metadata

      Peep.child_spec(
        name: name,
        metrics: metrics,
        global_tags: global_tags,
        storage: {Supavisor.PeepStorage, []}
      )
    end
  end

  @impl true
  def plugins do
    poll_rate = Application.fetch_env!(:supavisor, :prom_poll_rate)

    [
      # PromEx built in plugins
      Plugins.Application,
      Plugins.Beam,
      {Supavisor.PromEx.Plugins.Phoenix,
       router: SupavisorWeb.Router, endpoint: SupavisorWeb.Endpoint},
      Plugins.Ecto,

      # Custom PromEx metrics plugins
      {OsMon, poll_rate: poll_rate},
      {Tenant, poll_rate: poll_rate},
      {Cluster, poll_rate: poll_rate}
    ]
  end

  @spec get_metrics() :: iodata()
  def get_metrics do
    fetch_metrics()
    |> PrometheusCached.export()
  end

  @spec get_cluster_metrics() :: iodata()
  def get_cluster_metrics do
    fetch_cluster_metrics()
  end

  @spec do_cache_tenants_metrics() :: list
  def do_cache_tenants_metrics do
    pools =
      Registry.select(Supavisor.Registry.TenantClients, [{{:"$1", :_, :_}, [], [:"$1"]}])
      |> Enum.uniq()

    Enum.each(pools, fn {{_type, tenant}, _, _, _, _} ->
      {_, _, metrics_map} = fetch_metrics_for(tenant: tenant)

      if metrics_map != %{} do
        Cachex.put(Supavisor.Cache, {:metrics, tenant}, metrics_map)
      end
    end)

    pools
  end

  @spec get_cluster_tenant_metrics(String.t()) :: iodata()
  def get_cluster_tenant_metrics(tenant) do
    fetch_cluster_tenant_metrics(tenant)
  end

  @spec get_tenant_metrics(String.t()) :: iodata() | String.t()
  def get_tenant_metrics(tenant) do
    case Cachex.get(Supavisor.Cache, {:metrics, tenant}) do
      {_, metrics} when is_map(metrics) ->
        {reverse_tags_tid, cache_tid} = local_tids()
        PrometheusCached.export({reverse_tags_tid, cache_tid, metrics})

      _ ->
        ""
    end
  end

  def fetch_metrics do
    persistent = Peep.Persistent.fetch(__metrics_collector_name__())
    {_, storage} = Peep.Persistent.storage(__metrics_collector_name__())
    PeepStorage.get_all_metrics_with_tag_ids(storage, persistent)
  end

  @doc """
  Exports local metrics as iodata without the trailing `# EOF` marker.
  Used for cross-node collection where each node exports locally
  (where ETS tids are valid) and results are concatenated.
  """
  def fetch_metrics_as_iodata do
    :proc_lib.set_label(:metrics_fetcher)

    fetch_metrics()
    |> PrometheusCached.export_metrics()
    |> IO.iodata_to_binary()
  end

  def fetch_tenant_metrics(tenant) do
    case Cachex.get(Supavisor.Cache, {:metrics, tenant}) do
      {_, metrics} when is_map(metrics) -> metrics
      _ -> %{}
    end
  end

  def fetch_tenant_metrics_as_iodata(tenant) do
    :proc_lib.set_label({:metrics_fetcher, tenant})

    case fetch_tenant_metrics(tenant) do
      metrics when map_size(metrics) > 0 ->
        {reverse_tags_tid, cache_tid} = local_tids()

        {reverse_tags_tid, cache_tid, metrics}
        |> PrometheusCached.export_metrics()
        |> IO.iodata_to_binary()

      _ ->
        ""
    end
  end

  def fetch_cluster_metrics do
    [node() | Node.list()]
    |> Task.async_stream(
      fn node ->
        :proc_lib.set_label({:metrics_fetcher_task, node})
        fetch_node_metrics(node)
      end,
      timeout: :infinity
    )
    |> Enum.map_join(fn {_, iodata} -> iodata end)
    |> then(fn data -> [data, "# EOF\n"] end)
  end

  def fetch_cluster_tenant_metrics(tenant) do
    [node() | Node.list()]
    |> Task.async_stream(
      fn node ->
        :proc_lib.set_label({:metrics_fetcher_task, node, tenant})
        fetch_node_tenant_metrics(node, tenant)
      end,
      timeout: :infinity
    )
    |> Enum.map_join(fn {_, iodata} -> iodata end)
    |> then(fn data -> [data, "# EOF\n"] end)
  end

  @spec fetch_node_metrics(atom()) :: binary()
  defp fetch_node_metrics(node), do: do_fetch(node, :fetch_metrics_as_iodata, [])

  @spec fetch_node_tenant_metrics(atom(), String.t()) :: binary()
  defp fetch_node_tenant_metrics(node, tenant),
    do: do_fetch(node, :fetch_tenant_metrics_as_iodata, [tenant])

  @spec do_fetch(node(), atom(), list()) :: binary()
  defp do_fetch(node, f, a) do
    case :rpc.call(node, __MODULE__, f, a, 25_000) do
      data when is_binary(data) ->
        data

      {:badrpc, reason} ->
        Logger.error(
          "Cannot fetch metrics from the node #{inspect(node)} because #{inspect(reason)} (call #{f} with #{inspect(a)})"
        )

        ""
    end
  end

  def fetch_metrics_for(tags) do
    tag_filters =
      for {name, value} <- tags do
        {name, value}
      end

    persistent = Peep.Persistent.fetch(__metrics_collector_name__())

    {_, {tags_tid, metric_tids, reverse_tags_tid, cache_tid}} =
      Peep.Persistent.storage(__metrics_collector_name__())

    itm = Peep.Persistent.ids_to_metrics(persistent)
    boundaries_cache = precompute_boundaries(itm)

    # Collect matching tag IDs by scanning the tags table
    matching_tag_ids =
      :ets.foldl(
        fn {tags_map, tags_id}, acc ->
          if Enum.all?(tag_filters, fn {k, v} -> Map.get(tags_map, k) == v end) do
            MapSet.put(acc, tags_id)
          else
            acc
          end
        end,
        MapSet.new(),
        tags_tid
      )

    # Collect metrics from all scheduler tables, filtering by matching tag IDs
    metrics =
      metric_tids
      |> Tuple.to_list()
      |> Enum.reduce(%{}, fn tid, acc ->
        :ets.foldl(
          fn {{id, tags_id}, value}, acc ->
            if MapSet.member?(matching_tag_ids, tags_id) do
              %{^id => metric} = itm
              merge_filtered_entry(metric, id, tags_id, value, boundaries_cache, acc)
            else
              acc
            end
          end,
          acc,
          tid
        )
      end)

    metrics = remove_timestamps_from_last_values(metrics)

    {reverse_tags_tid, cache_tid, metrics}
  end

  defp merge_filtered_entry(%Metrics.Counter{} = metric, _id, tags_id, value, _bc, acc) do
    path = [Access.key(metric, %{}), Access.key(tags_id, 0)]
    update_in(acc, path, &(&1 + value))
  end

  defp merge_filtered_entry(%Metrics.Sum{} = metric, _id, tags_id, value, _bc, acc) do
    path = [Access.key(metric, %{}), Access.key(tags_id, 0)]
    update_in(acc, path, &(&1 + value))
  end

  defp merge_filtered_entry(%Metrics.LastValue{} = metric, _id, tags_id, {_, _} = a, _bc, acc) do
    path = [
      Access.key(:last_values, %{}),
      Access.key(metric, %{}),
      Access.key(tags_id, a)
    ]

    update_in(acc, path, fn {_, _} = b -> max(a, b) end)
  end

  defp merge_filtered_entry(%Metrics.Distribution{} = metric, id, tags_id, atomics, bc, acc) do
    {counts, sum, above_max} = Supavisor.PeepStorage.Atomics.counts(atomics)
    boundaries = Map.fetch!(bc, id)
    path = [Access.key(metric, %{}), Access.key(tags_id)]

    update_in(acc, path, fn
      nil ->
        {counts, sum, above_max, boundaries}

      {prev_counts, prev_sum, prev_above_max, _boundaries} ->
        merged = merge_counts(prev_counts, counts, [])
        {merged, prev_sum + sum, prev_above_max + above_max, boundaries}
    end)
  end

  defp merge_counts([], [], acc), do: Enum.reverse(acc)
  defp merge_counts([a | ra], [b | rb], acc), do: merge_counts(ra, rb, [a + b | acc])

  defp precompute_boundaries(itm) do
    Enum.reduce(itm, %{}, fn
      {id, %Metrics.Distribution{} = metric}, acc ->
        {module, config} = Peep.Buckets.config(metric)
        num_buckets = module.number_of_buckets(config)
        boundaries = for idx <- 0..(num_buckets - 1), do: module.upper_bound(idx, config)
        Map.put(acc, id, boundaries)

      _, acc ->
        acc
    end)
  end

  defp remove_timestamps_from_last_values(%{last_values: lvs} = metrics) do
    last_value_metrics =
      for {metric, tags_to_values} <- lvs,
          {tags_id, {_ts, value}} <- tags_to_values,
          reduce: %{} do
        acc ->
          put_in(acc, [Access.key(metric, %{}), Access.key(tags_id)], value)
      end

    metrics
    |> Map.delete(:last_values)
    |> Map.merge(last_value_metrics)
  end

  defp remove_timestamps_from_last_values(metrics), do: metrics

  defp local_tids do
    {_, {_tags_tid, _metric_tids, reverse_tags_tid, cache_tid}} =
      Peep.Persistent.storage(__metrics_collector_name__())

    {reverse_tags_tid, cache_tid}
  end
end
