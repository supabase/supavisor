defmodule Supavisor.Terminator do
  @moduledoc """
  Handles graceful shutdown signaling for tenant pools.

  Signals the pool manager to stop accepting new connections, and to
  stop current client connections gracefully.
  """
  use GenServer, shutdown: :timer.seconds(5)

  require Logger

  alias Supavisor.Manager

  def start_link(args) do
    GenServer.start_link(__MODULE__, args)
  end

  @impl true
  def init(args) do
    Process.flag(:trap_exit, true)
    {:ok, %{id: args.id}}
  end

  @drain_timeout 2_500
  @call_timeout 4_000

  @impl true
  def terminate(_reason, state) do
    :ok = Manager.graceful_shutdown(state.id, @drain_timeout, @call_timeout)
  end
end
