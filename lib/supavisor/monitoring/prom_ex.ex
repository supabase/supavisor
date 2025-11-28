defmodule Supavisor.Monitoring.PromEx do
  @moduledoc """
  This module configures the PromEx application for Supavisor. It defines
  the plugins used for collecting metrics, including built-in plugins and custom ones,
  and provides a function to remove remote metrics associated with a specific tenant.
  """

  use PromEx, otp_app: :supavisor
  require Logger

  alias Peep.Storage
  alias PromEx.Plugins
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
        storage: :striped
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
    |> Peep.Prometheus.export()
  end

  @spec get_cluster_metrics() :: iodata()
  def get_cluster_metrics do
    fetch_cluster_metrics()
    |> Peep.Prometheus.export()
  end

  @spec do_cache_tenants_metrics() :: list
  def do_cache_tenants_metrics do
    pools =
      Registry.select(Supavisor.Registry.TenantClients, [{{:"$1", :_, :_}, [], [:"$1"]}])
      |> Enum.uniq()

    Enum.each(pools, fn {{_type, tenant}, _, _, _, _} ->
      metrics = fetch_metrics_for(tenant: tenant)

      if metrics != %{} do
        Cachex.put(Supavisor.Cache, {:metrics, tenant}, metrics)
      end
    end)

    pools
  end

  @spec get_cluster_tenant_metrics(String.t()) :: iodata()
  def get_cluster_tenant_metrics(tenant) do
    fetch_cluster_tenant_metrics(tenant)
    |> Peep.Prometheus.export()
  end

  @spec get_tenant_metrics(String.t()) :: String.t()
  def get_tenant_metrics(tenant) do
    case Cachex.get(Supavisor.Cache, {:metrics, tenant}) do
      {_, metrics} when is_map(metrics) -> Peep.Prometheus.export(metrics)
      _ -> ""
    end
  end

  def fetch_metrics do
    Peep.get_all_metrics(__metrics_collector_name__())
  end

  def fetch_tenant_metrics(tenant) do
    case Cachex.get(Supavisor.Cache, {:metrics, tenant}) do
      {_, metrics} when is_map(metrics) -> metrics
      _ -> %{}
    end
  end

  def fetch_cluster_metrics do
    [node() | Node.list()]
    |> Task.async_stream(&fetch_node_metrics/1, timeout: :infinity)
    |> Stream.map(fn {_, map} -> map end)
    |> Enum.reduce(&merge_metrics/2)
  end

  def fetch_cluster_tenant_metrics(tenant) do
    [node() | Node.list()]
    |> Task.async_stream(&fetch_node_tenant_metrics(&1, tenant), timeout: :infinity)
    |> Stream.map(fn {_, map} -> map end)
    |> Enum.reduce(&merge_metrics/2)
  end

  @spec fetch_node_metrics(atom()) :: map()
  defp fetch_node_metrics(node), do: do_fetch(node, :fetch_metrics, [])

  @spec fetch_node_tenant_metrics(atom(), String.t()) :: map()
  defp fetch_node_tenant_metrics(node, tenant),
    do: do_fetch(node, :fetch_tenant_metrics, [tenant])

  @spec do_fetch(node(), atom(), list()) :: map()
  defp do_fetch(node, f, a) do
    case :rpc.call(node, __MODULE__, f, a, 25_000) do
      map when is_map(map) ->
        map

      {:badrpc, reason} ->
        Logger.error(
          "Cannot fetch metrics from the node #{inspect(node)} because #{inspect(reason)} (call #{f} with #{inspect(a)})"
        )

        %{}
    end
  end

  defp merge_metrics(a, b), do: Map.merge(a, b, &do_merge/3)

  defp do_merge(%Metrics.Counter{}, a, b), do: sum_merge(a, b)
  defp do_merge(%Metrics.Sum{}, a, b), do: sum_merge(a, b)
  defp do_merge(%Metrics.LastValue{}, a, b), do: Map.merge(a, b)

  defp do_merge(%Metrics.Distribution{}, a, b) do
    Map.merge(a, b, fn _, a, b -> sum_merge(a, b) end)
  end

  defp sum_merge(a, b), do: Map.merge(a, b, fn _, a, b -> a + b end)

  # Works only with striped storage
  def fetch_metrics_for(tags) do
    match =
      for {name, value} <- tags do
        {:"=:=", {:map_get, {:const, name}, :"$1"}, {:const, value}}
      end

    %Peep.Persistent{storage: {_, store}, ids_to_metrics: itm} =
      Peep.Persistent.fetch(__metrics_collector_name__())

    store
    |> Tuple.to_list()
    |> Enum.flat_map(fn tid ->
      :ets.select(tid, [{{{:_, :"$1", :_}, :_}, match, [:"$_"]}])
    end)
    |> group_metrics(itm, %{})
  end

  # Copied from Peep.
  # To be removed if Peep will accept feature request for similar functionality,
  # see: https://github.com/rkallos/peep/issues/35
  defp group_metrics([], _itm, acc) do
    acc
  end

  defp group_metrics([metric | rest], itm, acc) do
    acc2 = group_metric(metric, itm, acc)
    group_metrics(rest, itm, acc2)
  end

  defp group_metric({{id, tags, _}, value}, itm, acc) do
    %{^id => metric} = itm
    update_in(acc, [Access.key(metric, %{}), Access.key(tags, 0)], &(&1 + value))
  end

  defp group_metric({{id, tags}, %Storage.Atomics{} = atomics}, itm, acc) do
    %{^id => metric} = itm
    put_in(acc, [Access.key(metric, %{}), Access.key(tags)], Storage.Atomics.values(atomics))
  end

  defp group_metric({{id, tags}, value}, itm, acc) do
    %{^id => metric} = itm
    put_in(acc, [Access.key(metric, %{}), Access.key(tags)], value)
  end
end
