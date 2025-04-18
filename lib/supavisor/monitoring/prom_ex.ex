defmodule Supavisor.Monitoring.PromEx do
  @moduledoc """
  This module configures the PromEx application for Supavisor. It defines
  the plugins used for collecting metrics, including built-in plugins and custom ones,
  and provides a function to remove remote metrics associated with a specific tenant.
  """

  use PromEx, otp_app: :supavisor
  require Logger

  alias PromEx.Plugins
  alias Supavisor.PromEx.Plugins.{OsMon, Tenant}

  defmodule Store do
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
      global_tags_keys = Map.keys(global_tags)

      Peep.child_spec(
        name: name,
        metrics: Enum.map(metrics, &extent_tags(&1, global_tags_keys)),
        global_tags: global_tags
      )
    end

    defp extent_tags(%{tags: tags} = metric, global_tags) do
      %{metric | tags: tags ++ global_tags}
    end
  end

  @impl true
  def plugins do
    poll_rate = Application.fetch_env!(:supavisor, :prom_poll_rate)

    [
      # PromEx built in plugins
      Plugins.Application,
      Plugins.Beam,
      {Plugins.Phoenix, router: SupavisorWeb.Router, endpoint: SupavisorWeb.Endpoint},
      Plugins.Ecto,

      # Custom PromEx metrics plugins
      {OsMon, poll_rate: poll_rate},
      {Tenant, poll_rate: poll_rate}
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
    metrics = get_metrics() |> IO.iodata_to_binary() |> String.split("\n")

    pools =
      Registry.select(Supavisor.Registry.TenantClients, [{{:"$1", :_, :_}, [], [:"$1"]}])
      |> Enum.uniq()

    _ =
      Enum.reduce(pools, metrics, fn {{_type, tenant}, _, _, _, _}, acc ->
        {matched, rest} = Enum.split_with(acc, &String.contains?(&1, "tenant=\"#{tenant}\""))

        if matched != [] do
          Cachex.put(Supavisor.Cache, {:metrics, tenant}, Enum.join(matched, "\n"))
        end

        rest
      end)

    pools
  end

  @spec get_tenant_metrics(String.t()) :: String.t()
  def get_tenant_metrics(tenant) do
    case Cachex.get(Supavisor.Cache, {:metrics, tenant}) do
      {_, metrics} when is_binary(metrics) -> metrics
      _ -> ""
    end
  end

  def fetch_metrics do
    Peep.get_all_metrics(__metrics_collector_name__())
  end

  def fetch_cluster_metrics do
    [node() | Node.list()]
    |> Task.async_stream(&fetch_node_metrics/1, timeout: :infinity)
    |> Stream.map(fn {_, map} -> map end)
    |> Enum.reduce(&merge_metrics/2)
  end

  @spec fetch_node_metrics(atom()) :: {atom(), term()}
  defp fetch_node_metrics(node) do
    case :rpc.call(node, __MODULE__, :fetch_metrics, [], 25_000) do
      map when is_map(map) ->
        map

      {:badrpc, reason} ->
        Logger.error(
          "Cannot fetch metrics from the node #{inspect(node)} because #{inspect(reason)}"
        )

        %{}
    end
  end

  defp merge_metrics(a, {_, b}), do: Map.merge(a, b, &do_merge/3)

  defp do_merge(%Telemetry.Metrics.Counter{}, a, b), do: sum_merge(a, b)
  defp do_merge(%Telemetry.Metrics.Sum{}, a, b), do: sum_merge(a, b)
  defp do_merge(%Telemetry.Metrics.LastValue{}, a, b), do: Map.merge(a, b)

  defp do_merge(%Telemetry.Metrics.Distribution{}, a, b) do
    Map.merge(a, b, fn _, a, b -> sum_merge(a, b) end)
  end

  defp sum_merge(a, b), do: Map.merge(a, b, fn _, a, b -> a + b end)
end
