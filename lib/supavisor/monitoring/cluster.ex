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
      ),
      Polling.build(
        :supavisor_app_version_events,
        poll_rate,
        {__MODULE__, :emit_app_version, []},
        [
          last_value(
            [:supavisor, :prom_ex, :application, :version, :info],
            event_name: [:supavisor, :prom_ex, :application, :version],
            measurement: :status,
            description:
              "The currently running version of the Supavisor application along with upgrade history.",
            tags: [:current, :permanent, :base, :previous]
          )
        ]
      )
    ]
  end

  @impl true
  def manual_metrics(_opts) do
    [
      Manual.build(
        :supavisor_ami_version_manual_metrics,
        {__MODULE__, :emit_ami_version, []},
        [
          last_value(
            [:supavisor, :prom_ex, :ami, :version, :info],
            event_name: [:supavisor, :prom_ex, :ami, :version],
            measurement: :status,
            description: "The AMI version the node is running on.",
            tags: [:version]
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

  @spec emit_app_version() :: :ok
  def emit_app_version do
    current = Application.spec(:supavisor, :vsn) |> to_string()
    releases = :release_handler.which_releases()

    permanent =
      case Enum.find(releases, fn {_, _, _, status} -> status == :permanent end) do
        {_, vsn, _, _} -> to_string(vsn)
        nil -> ""
      end

    old_versions =
      releases
      |> Enum.filter(fn {_, _, _, status} -> status == :old end)
      |> Enum.map(fn {_, vsn, _, _} -> to_string(vsn) end)
      |> Enum.sort({:asc, Version})

    base = List.first(old_versions, "")
    previous = List.last(old_versions, "")

    :telemetry.execute(
      [:supavisor, :prom_ex, :application, :version],
      %{status: 1},
      %{current: current, permanent: permanent, base: base, previous: previous}
    )
  end

  @spec emit_ami_version() :: :ok
  def emit_ami_version do
    case System.get_env("AMI_VERSION") do
      version when is_binary(version) and version != "" ->
        :telemetry.execute(
          [:supavisor, :prom_ex, :ami, :version],
          %{status: 1},
          %{version: version}
        )

      # Don't emit for deployments (e.g. self-hosted) that don't set AMI_VERSION.
      _ ->
        :ok
    end
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
