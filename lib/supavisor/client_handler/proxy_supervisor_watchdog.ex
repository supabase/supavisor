defmodule Supavisor.ClientHandler.ProxySupervisorWatchdog do
  @moduledoc """
  Watchdog process for proxy connection supervisors.

  Sibling of the proxy DynamicSupervisor under `ProxySupervisor`. Periodically
  checks if the DynamicSupervisor has no children. Requires two consecutive
  empty checks before terminating. Since it's a significant child, its
  termination triggers `auto_shutdown: :any_significant` on the parent `ProxySupervisor`.
  """

  use GenServer

  require Logger

  @registry Supavisor.Registry.Tenants
  @default_check_interval :timer.seconds(30)
  @default_jitter :timer.seconds(5)

  @doc """
  Triggers an immediate check. Returns `:alive` if the watchdog stays up,
  or `:stopping` if it decided to shut down.
  """
  def check_now(pid) do
    GenServer.call(pid, :check)
  end

  def start_link(id, opts \\ []) do
    GenServer.start_link(__MODULE__, {id, opts})
  end

  @impl true
  def init({id, opts}) do
    interval = Keyword.get(opts, :check_interval, @default_check_interval)
    jitter = Keyword.get(opts, :jitter, @default_jitter)
    schedule_check(interval, jitter)
    {:ok, %{id: id, empty_checks: 0, check_interval: interval, jitter: jitter}}
  end

  @impl true
  def handle_call(:check, _from, state), do: do_check(state)

  @impl true
  def handle_info(:check, state), do: do_check(state)

  defp do_check(
         %{id: id, empty_checks: empty_checks, check_interval: interval, jitter: jitter} = state
       ) do
    [{dyn_sup, _}] = Registry.lookup(@registry, {:proxy_dyn_sup, id})

    case DynamicSupervisor.count_children(dyn_sup) do
      %{active: 0} when empty_checks >= 1 ->
        Logger.debug(
          "ProxySupervisorWatchdog: shutting down empty proxy supervisor for #{inspect(id)}"
        )

        {:stop, :normal, :stopping, state}

      %{active: 0} ->
        schedule_check(interval, jitter)
        {:reply, :alive, %{state | empty_checks: empty_checks + 1}}

      _ ->
        schedule_check(interval, jitter)
        {:reply, :alive, %{state | empty_checks: 0}}
    end
  end

  defp schedule_check(interval, 0), do: Process.send_after(self(), :check, interval)

  defp schedule_check(interval, jitter) do
    Process.send_after(self(), :check, interval + :rand.uniform(jitter))
  end
end
