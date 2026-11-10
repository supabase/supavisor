defmodule Supavisor.MessageQueueWatchdog do
  @moduledoc """
  Periodically checks message queue lengths of relevant singleton processes,
  and of each partition of relevant partitioned supervisors.

  Logs a warning when a queue exceeds 20k messages. Shuts down the node
  when the queue of a process the system cannot operate without exceeds
  500k messages.
  """

  use GenServer

  require Logger

  @check_interval :timer.seconds(10)

  @warn_queue_len 20_000
  @shutdown_queue_len 500_000
  @shutdown_processes ["tls_connection_sup", "inet_gethost_native"]

  @shutdown_partitioned [Supavisor.TLSHandshake.Supervisor]

  @processes [
    :tls_connection_sup,
    :ssl_manager,
    :ssl_pem_cache,
    :inet_gethost_native,
    :rex,
    :syn_registry_tenants,
    :syn_pg_tenants,
    :syn_registry_availability_zone,
    :syn_pg_availability_zone,
    :syn_registry_accepting_pools,
    :syn_pg_accepting_pools,
    Supavisor.ErlSysMon,
    Supavisor.PoolTerminator,
    :"Elixir.Supavisor.Cache_courier"
  ]

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  @doc """
  Reads the current message queue lengths of the watched processes that
  are running, keyed by a printable process name. Partitions are named
  `<supervisor>.<partition>`.
  """
  @spec queue_lengths() :: [{String.t(), non_neg_integer()}]
  def queue_lengths do
    for {name, len, _shutdown?} <- watched_queue_lengths(), do: {name, len}
  end

  defp watched_queue_lengths do
    named =
      for name <- @processes,
          pid = Process.whereis(name),
          {:message_queue_len, len} <- [Process.info(pid, :message_queue_len)] do
        str = format_name(name)
        {str, len, str in @shutdown_processes}
      end

    partitions =
      for sup <- @shutdown_partitioned,
          Process.whereis(sup),
          {id, pid, _, _} <- PartitionSupervisor.which_children(sup),
          is_pid(pid),
          {:message_queue_len, len} <- [Process.info(pid, :message_queue_len)] do
        {"#{format_name(sup)}.#{id}", len, true}
      end

    named ++ partitions
  end

  @impl true
  def init(_args) do
    schedule_check()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:check, state) do
    Enum.each(watched_queue_lengths(), fn {name, len, shutdown?} ->
      check_queue_len(name, len, shutdown?)
    end)

    schedule_check()
    {:noreply, state}
  end

  defp check_queue_len(name, len, true = _shutdown?) when len > @shutdown_queue_len do
    Logger.critical("#{__MODULE__}: #{name} message queue length is #{len}, shutting down node")

    System.stop()
  end

  defp check_queue_len(name, len, _shutdown?) when len > @warn_queue_len do
    Logger.warning("#{__MODULE__}: #{name} message queue length is #{len}")
  end

  defp check_queue_len(_name, _len, _shutdown?), do: :ok

  defp format_name(name) do
    case Atom.to_string(name) do
      "Elixir." <> rest -> rest
      other -> other
    end
  end

  defp schedule_check do
    Process.send_after(self(), :check, @check_interval)
  end
end
