defmodule Supavisor.MessageQueueWatchdog do
  @moduledoc """
  Periodically checks message queue lengths of relevant singleton processes.

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
    Supavisor.ErlSysMon,
    Supavisor.PoolTerminator,
    :"Elixir.Supavisor.Cache_courier"
  ]

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  @doc """
  Reads the current message queue lengths of the watched processes that
  are running, keyed by a printable process name.
  """
  @spec queue_lengths() :: [{String.t(), non_neg_integer()}]
  def queue_lengths do
    for name <- @processes,
        pid = Process.whereis(name),
        {:message_queue_len, len} <- [Process.info(pid, :message_queue_len)] do
      {format_name(name), len}
    end
  end

  @impl true
  def init(_args) do
    schedule_check()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:check, state) do
    Enum.each(queue_lengths(), fn {name, len} -> check_queue_len(name, len) end)
    schedule_check()
    {:noreply, state}
  end

  defp check_queue_len(name, len)
       when name in @shutdown_processes and len > @shutdown_queue_len do
    Logger.critical("#{__MODULE__}: #{name} message queue length is #{len}, shutting down node")

    System.stop()
  end

  defp check_queue_len(name, len) when len > @warn_queue_len do
    Logger.warning("#{__MODULE__}: #{name} message queue length is #{len}")
  end

  defp check_queue_len(_name, _len), do: :ok

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
