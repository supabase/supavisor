defmodule Supavisor.PromEx.Plugins.Cluster do
  @moduledoc """
  Polls cluster metrics.
  """

  use PromEx.Plugin

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      Polling.build(
        :supavisor_cluster_size_events,
        poll_rate,
        {__MODULE__, :emit_cluster_size, []},
        [
          last_value(
            [:supavisor, :prom_ex, :cluster, :size],
            event_name: [:supavisor, :prom_ex, :cluster],
            measurement: :size,
            description: "The total number of nodes connected to the cluster."
          )
        ]
      ),
      Polling.build(
        :supavisor_cluster_erpc_events,
        poll_rate,
        {__MODULE__, :emit_erpc_latency, []},
        [
          distribution(
            [:supavisor, :prom_ex, :cluster, :erpc_ping, :duration, :ms],
            event_name: [:supavisor, :prom_ex, :cluster, :erpc_ping, :stop],
            measurement: :duration,
            description: "Latency of ERPC ping requests to cluster nodes in milliseconds.",
            tags: [:target_node, :result],
            unit: {:native, :millisecond}
          )
        ]
      )
    ]
  end

  @spec emit_cluster_size() :: :ok
  def emit_cluster_size do
    connected_nodes = Node.list()
    cluster_size = length(connected_nodes) + 1
    :telemetry.execute([:supavisor, :prom_ex, :cluster], %{size: cluster_size})
  end

  @spec emit_erpc_latency() :: :ok
  def emit_erpc_latency do
    [Node.self() | Node.list()]
    |> Enum.each(fn node ->
      :telemetry.span([:supavisor, :prom_ex, :cluster, :erpc_ping], %{target_node: node}, fn ->
        try do
          :erpc.call(node, fn -> :ok end, 30_000)
          {:ok, %{result: :success, target_node: node}}
        catch
          _, _ ->
            {:ok, %{result: :failure, target_node: node}}
        end
      end)
    end)
  end
end
