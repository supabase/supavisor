defmodule Supavisor.PromEx.Plugins.NetStat do
  @moduledoc """
  Polls system-wide network counters via procfs.
  """

  use PromEx.Plugin

  @event_net_stat [:supavisor, :prom_ex, :osmon, :net_stat]
  @event_sock_stat [:supavisor, :prom_ex, :osmon, :sock_stat]
  @prefix [:supavisor, :prom_ex]
  @proc_net_netstat "/proc/net/netstat"
  @proc_net_sockstat "/proc/net/sockstat"

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      net_stat_metrics(poll_rate),
      sock_stat_metrics(poll_rate)
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

  def execute_sock_stat_metrics(path \\ @proc_net_sockstat) do
    case sock_stat(path) do
      {:ok, stats} -> execute_metrics(@event_sock_stat, stats)
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

  defp sock_stat_metrics(poll_rate) do
    Polling.build(
      :supavisor_osmon_sock_stat_events,
      poll_rate,
      {__MODULE__, :execute_sock_stat_metrics, []},
      [
        last_value(
          @prefix ++ [:osmon, :net, :tcp_inuse],
          event_name: @event_sock_stat,
          description: "Number of TCP sockets currently in use.",
          measurement: :tcp_inuse
        ),
        last_value(
          @prefix ++ [:osmon, :net, :tcp_orphan],
          event_name: @event_sock_stat,
          description: "Number of orphaned (unattached to a file descriptor) TCP sockets.",
          measurement: :tcp_orphan
        ),
        last_value(
          @prefix ++ [:osmon, :net, :tcp_time_wait],
          event_name: @event_sock_stat,
          description: "Number of TCP sockets currently in the TIME_WAIT state.",
          measurement: :tcp_time_wait
        ),
        last_value(
          @prefix ++ [:osmon, :net, :tcp_alloc],
          event_name: @event_sock_stat,
          description: "Number of allocated TCP socket structures.",
          measurement: :tcp_alloc
        ),
        last_value(
          @prefix ++ [:osmon, :net, :tcp_mem_pages],
          event_name: @event_sock_stat,
          description: "Number of memory pages consumed by the TCP protocol.",
          measurement: :tcp_mem_pages
        )
      ]
    )
  end

  # sobelow_skip ["Traversal.FileModule"]
  @spec sock_stat(Path.t()) ::
          {:ok,
           %{
             tcp_inuse: non_neg_integer(),
             tcp_orphan: non_neg_integer(),
             tcp_time_wait: non_neg_integer(),
             tcp_alloc: non_neg_integer(),
             tcp_mem_pages: non_neg_integer()
           }}
          | :error
  def sock_stat(path \\ @proc_net_sockstat) do
    with {:ok, content} <- File.read(path),
         {:ok, stats} <- parse_sock_stat(content) do
      {:ok, stats}
    else
      _ -> :error
    end
  end

  @spec parse_sock_stat(String.t()) ::
          {:ok,
           %{
             tcp_inuse: non_neg_integer(),
             tcp_orphan: non_neg_integer(),
             tcp_time_wait: non_neg_integer(),
             tcp_alloc: non_neg_integer(),
             tcp_mem_pages: non_neg_integer()
           }}
          | :error
  def parse_sock_stat(content) do
    content
    |> String.split("\n", trim: true)
    |> Enum.find_value(fn
      "TCP: " <> rest ->
        counters =
          rest
          |> String.split()
          |> Enum.chunk_every(2)
          |> Map.new(fn [k, v] -> {k, String.to_integer(v)} end)

        {:ok,
         %{
           tcp_inuse: Map.get(counters, "inuse", 0),
           tcp_orphan: Map.get(counters, "orphan", 0),
           tcp_time_wait: Map.get(counters, "tw", 0),
           tcp_alloc: Map.get(counters, "alloc", 0),
           tcp_mem_pages: Map.get(counters, "mem", 0)
         }}

      _ ->
        nil
    end) || :error
  end
end
