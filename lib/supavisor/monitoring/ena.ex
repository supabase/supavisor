defmodule Supavisor.PromEx.Plugins.Ena do
  @moduledoc """
  Polls the network allowance counters of the EC2 ENA driver via `ethtool -S`.

  EC2 queues or drops packets that exceed the instance's bandwidth, packets per
  second, connection tracking, or link-local service allowances. The ENA driver
  reports these as private interface statistics.
  """

  use PromEx.Plugin

  @event [:supavisor, :prom_ex, :osmon, :ena]
  @prefix [:supavisor, :prom_ex, :osmon, :ena]

  @counters [
    bw_in_allowance_exceeded:
      "Cumulative number of packets queued or dropped because the inbound bandwidth exceeded the instance allowance.",
    bw_out_allowance_exceeded:
      "Cumulative number of packets queued or dropped because the outbound bandwidth exceeded the instance allowance.",
    pps_allowance_exceeded:
      "Cumulative number of packets queued or dropped because the bidirectional packets per second exceeded the instance allowance.",
    conntrack_allowance_exceeded:
      "Cumulative number of packets dropped because connection tracking exceeded the instance allowance.",
    linklocal_allowance_exceeded:
      "Cumulative number of packets dropped because traffic to link-local services exceeded the interface allowance."
  ]

  @gauges [
    conntrack_allowance_available:
      "Number of tracked connections the instance can establish before reaching its connection tracking allowance."
  ]

  @stat_names Map.new(Keyword.keys(@counters) ++ Keyword.keys(@gauges), &{Atom.to_string(&1), &1})

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)
    interface = Keyword.fetch!(opts, :interface)

    [
      Polling.build(
        :supavisor_osmon_ena_events,
        poll_rate,
        {__MODULE__, :execute_metrics, [interface]},
        counter_metrics() ++ gauge_metrics()
      )
    ]
  end

  defp counter_metrics do
    for {stat, description} <- @counters do
      last_value(
        @prefix ++ [stat],
        event_name: @event,
        description: description,
        measurement: &Map.get(&1, stat),
        reporter_options: [prometheus_type: "counter"]
      )
    end
  end

  defp gauge_metrics do
    for {stat, description} <- @gauges do
      last_value(
        @prefix ++ [stat],
        event_name: @event,
        description: description,
        measurement: &Map.get(&1, stat)
      )
    end
  end

  def execute_metrics(interface, ethtool \\ "ethtool") do
    case ethtool_stats(interface, ethtool) do
      {:ok, stats} -> :telemetry.execute(@event, stats, %{})
      :error -> :ok
    end
  end

  @type stats :: %{optional(atom()) => non_neg_integer()}

  # sobelow_skip ["CI.System"]
  @spec ethtool_stats(String.t(), String.t()) :: {:ok, stats()} | :error
  def ethtool_stats(interface, ethtool \\ "ethtool") do
    with path when is_binary(path) <- System.find_executable(ethtool),
         {output, 0} <- System.cmd(path, ["-S", interface], stderr_to_stdout: true) do
      parse_ethtool_stats(output)
    else
      _ -> :error
    end
  end

  @spec parse_ethtool_stats(String.t()) :: {:ok, stats()} | :error
  def parse_ethtool_stats(content) do
    stats =
      for line <- String.split(content, "\n"),
          [key, value] <- [String.split(line, ":", parts: 2)],
          {:ok, stat} <- [Map.fetch(@stat_names, String.trim(key))],
          {int, ""} <- [Integer.parse(String.trim(value))],
          into: %{},
          do: {stat, int}

    if map_size(stats) > 0, do: {:ok, stats}, else: :error
  end
end
