defmodule Supavisor.PromEx.Plugins.NetStat do
  @moduledoc """
  Polls system-wide network counters via procfs.
  """

  use PromEx.Plugin

  @event_net_stat [:supavisor, :prom_ex, :osmon, :net_stat]
  @prefix [:supavisor, :prom_ex]
  @proc_net_netstat "/proc/net/netstat"

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      net_stat_metrics(poll_rate)
    ]
  end

  defp net_stat_metrics(poll_rate) do
    Polling.build(
      :supavisor_osmon_net_stat_events,
      poll_rate,
      {__MODULE__, :execute_net_stat_metrics, []},
      [
        last_value(
          @prefix ++ [:osmon, :net, :listen_drops],
          event_name: @event_net_stat,
          description: "Cumulative number of connections dropped due to a full accept queue.",
          measurement: :listen_drops,
          reporter_options: [prometheus_type: "counter"]
        ),
        last_value(
          @prefix ++ [:osmon, :net, :listen_overflows],
          event_name: @event_net_stat,
          description: "Cumulative number of times the listen backlog of a socket overflowed.",
          measurement: :listen_overflows,
          reporter_options: [prometheus_type: "counter"]
        )
      ]
    )
  end

  def execute_net_stat_metrics(path \\ @proc_net_netstat) do
    case net_stat(path) do
      {:ok, stats} -> execute_metrics(@event_net_stat, stats)
      :error -> :ok
    end
  end

  defp execute_metrics(event, metrics) do
    :telemetry.execute(event, metrics, %{})
  end

  # sobelow_skip ["Traversal.FileModule"]
  @spec net_stat(Path.t()) ::
          {:ok, %{listen_drops: non_neg_integer(), listen_overflows: non_neg_integer()}} | :error
  def net_stat(path \\ @proc_net_netstat) do
    with {:ok, content} <- File.read(path),
         {:ok, stats} <- parse_net_stat(content) do
      {:ok, stats}
    else
      _ -> :error
    end
  end

  @spec parse_net_stat(String.t()) ::
          {:ok, %{listen_drops: non_neg_integer(), listen_overflows: non_neg_integer()}} | :error
  def parse_net_stat(content) do
    content
    |> String.split("\n", trim: true)
    |> Enum.chunk_every(2)
    |> Enum.find_value(fn
      ["TcpExt: " <> _ = header, values] ->
        keys = header |> String.split() |> tl()
        vals = values |> String.split() |> tl() |> Enum.map(&String.to_integer/1)
        counters = Enum.zip(keys, vals) |> Map.new()

        {:ok,
         %{
           listen_drops: Map.get(counters, "ListenDrops", 0),
           listen_overflows: Map.get(counters, "ListenOverflows", 0)
         }}

      _ ->
        nil
    end) || :error
  end
end
