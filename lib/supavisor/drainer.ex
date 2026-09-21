defmodule Supavisor.Drainer do
  @moduledoc """
  Drains every local pool before the client listeners are torn down.

  The client listeners are supervised by ranch, so stopping them kills the
  `Supavisor.ClientHandler` processes they supervise. Pools live earlier in the
  application supervisor, meaning they are terminated after the listeners: by
  the time a pool's `Supavisor.Terminator` runs, its clients are already gone
  and there is nothing left to drain.

  This process sits near the end of the application supervisor, just before
  `Supavisor.NodeMembership`, so it is terminated right after the node stops
  accepting new pools and well before the listeners. Its `terminate/2` drains
  every pool synchronously and only returns once they are done, which holds the
  rest of the shutdown back until clients have finished their queries.
  """

  use GenServer, shutdown: :timer.seconds(15)

  require Logger

  alias Supavisor.Manager

  @drain_timeout :timer.seconds(5)
  @max_concurrency 200

  def start_link(args), do: GenServer.start_link(__MODULE__, args, name: __MODULE__)

  @impl true
  def init(_args) do
    Process.flag(:trap_exit, true)
    {:ok, nil}
  end

  @impl true
  def terminate(_reason, _state) do
    managers = local_managers()

    Logger.info("Draining #{length(managers)} pools before shutdown")

    managers
    |> Task.async_stream(&Manager.graceful_shutdown(&1, @drain_timeout),
      max_concurrency: @max_concurrency,
      timeout: :infinity,
      on_timeout: :kill_task
    )
    |> Stream.run()

    Logger.info("Finished draining pools")
  end

  defp local_managers do
    Supavisor.Registry.TenantSups
    |> Registry.select([{{:_, :_, :"$1"}, [], [:"$1"]}])
    |> Enum.flat_map(fn id ->
      case Supavisor.get_local_manager(id) do
        nil -> []
        pid -> [pid]
      end
    end)
  end
end
