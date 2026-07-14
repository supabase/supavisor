defmodule Supavisor.PromEx.Plugins.OsMon do
  @moduledoc """
  Polls os_mon metrics.
  """

  use PromEx.Plugin
  require Logger

  @event_memory [:prom_ex, :plugin, :osmon, :memory]
  @event_ram_usage [:prom_ex, :plugin, :osmon, :ram_usage]
  @event_cpu_util [:prom_ex, :plugin, :osmon, :cpu_util]
  @event_cpu_la [:prom_ex, :plugin, :osmon, :cpu_avg1]
  @event_disk [:prom_ex, :plugin, :osmon, :disk]
  @event_net_stat [:supavisor, :prom_ex, :osmon, :net_stat]
  @prefix [:supavisor, :prom_ex]
  @proc_net_netstat "/proc/net/netstat"

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      metrics(poll_rate),
      net_stat_metrics(poll_rate)
    ]
  end

  defp metrics(poll_rate) do
    Polling.build(
      :supavisor_osmon_events,
      poll_rate,
      {__MODULE__, :execute_metrics, []},
      [
        last_value(
          @prefix ++ [:osmon, :ram_usage],
          event_name: @event_ram_usage,
          description: "The total percentage usage of operative memory.",
          measurement: :ram
        ),
        last_value(
          @prefix ++ [:osmon, :memory, :available],
          event_name: @event_memory,
          description: "The total available memory in the operating system",
          unit: :bytes,
          measurement: :available
        ),
        last_value(
          @prefix ++ [:osmon, :memory, :buffered],
          event_name: @event_memory,
          description: "The buffered memory in the operating system",
          unit: :bytes,
          measurement: :buffered
        ),
        last_value(
          @prefix ++ [:osmon, :memory, :cached],
          event_name: @event_memory,
          description: "The cached memory in the operating system",
          unit: :bytes,
          measurement: :cached
        ),
        last_value(
          @prefix ++ [:osmon, :memory, :free],
          event_name: @event_memory,
          description: "The free memory in the operating system",
          unit: :bytes,
          measurement: :free
        ),
        last_value(
          @prefix ++ [:osmon, :memory, :total],
          event_name: @event_memory,
          description: "The total memory in the operating system",
          unit: :bytes,
          measurement: :total
        ),
        last_value(
          @prefix ++ [:osmon, :memory, :system_total],
          event_name: @event_memory,
          description: "The total system memory",
          unit: :bytes,
          measurement: :system_total
        ),
        last_value(
          @prefix ++ [:osmon, :cpu_util],
          event_name: @event_cpu_util,
          description:
            "The sum of the percentage shares of the CPU cycles spent in all busy processor states in average on all CPUs.",
          measurement: :cpu
        ),
        last_value(
          @prefix ++ [:osmon, :cpu_avg1],
          event_name: @event_cpu_la,
          description: "The average system load in the last minute.",
          measurement: :avg1
        ),
        last_value(
          @prefix ++ [:osmon, :cpu_avg5],
          event_name: @event_cpu_la,
          description: "The average system load in the last five minutes.",
          measurement: :avg5
        ),
        last_value(
          @prefix ++ [:osmon, :cpu_avg15],
          event_name: @event_cpu_la,
          description: "The average system load in the last 15 minutes.",
          measurement: :avg15
        ),
        last_value(
          @prefix ++ [:osmon, :disk, :total],
          event_name: @event_disk,
          description: "The total size of the file system.",
          unit: :bytes,
          measurement: :total,
          tags: [:mountpoint]
        ),
        last_value(
          @prefix ++ [:osmon, :disk, :available],
          event_name: @event_disk,
          description: "The available space on the file system.",
          unit: :bytes,
          measurement: :available,
          tags: [:mountpoint]
        ),
        last_value(
          @prefix ++ [:osmon, :disk, :used_percent],
          event_name: @event_disk,
          description: "The percentage of used space on the file system.",
          measurement: :capacity,
          tags: [:mountpoint]
        )
      ]
    )
  end

  def execute_metrics do
    execute_metrics(@event_memory, memory())
    execute_metrics(@event_ram_usage, %{ram: ram_usage()})
    execute_metrics(@event_cpu_util, %{cpu: cpu_util()})
    execute_metrics(@event_cpu_la, cpu_la())
    execute_disk_metrics()
  end

  def execute_net_stat_metrics(path \\ @proc_net_netstat) do
    case net_stat(path) do
      {:ok, stats} -> execute_metrics(@event_net_stat, stats)
      :error -> :ok
    end
  end

  def execute_metrics(event, metrics) do
    :telemetry.execute(event, metrics, %{})
  end

  def execute_disk_metrics do
    Enum.each(disk(), fn {mountpoint, measurements} ->
      :telemetry.execute(@event_disk, measurements, %{mountpoint: mountpoint})
    end)
  end

  @spec ram_usage() :: float()
  def ram_usage do
    mem = :memsup.get_system_memory_data()
    100 - mem[:free_memory] / mem[:total_memory] * 100
  end

  @spec memory() :: map()
  def memory do
    data = :memsup.get_system_memory_data()

    %{
      available: data[:available_memory],
      buffered: data[:buffered_memory],
      cached: data[:cached_memory],
      free: data[:free_memory],
      total: data[:total_memory],
      system_total: data[:system_total_memory]
    }
  end

  @spec cpu_la() :: %{avg1: float(), avg5: float(), avg15: float()}
  def cpu_la do
    %{
      avg1: :cpu_sup.avg1() / 256,
      avg5: :cpu_sup.avg5() / 256,
      avg15: :cpu_sup.avg15() / 256
    }
  end

  @spec cpu_util() :: float() | {:error, term()}
  def cpu_util do
    :cpu_sup.util()
  end

  @spec disk() :: [{String.t(), %{total: integer(), available: integer(), capacity: integer()}}]
  def disk do
    for {id, total_kib, available_kib, capacity} <- :disksup.get_disk_info() do
      {to_string(id),
       %{
         total: total_kib * 1024,
         available: available_kib * 1024,
         capacity: capacity
       }}
    end
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
          measurement: :listen_drops
        ),
        last_value(
          @prefix ++ [:osmon, :net, :listen_overflows],
          event_name: @event_net_stat,
          description: "Cumulative number of times the listen backlog of a socket overflowed.",
          measurement: :listen_overflows
        )
      ]
    )
  end
end
