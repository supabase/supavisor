defmodule Supavisor.TenantsMetrics do
  @moduledoc false
  use GenServer, restart: :transient
  require Logger

  alias Supavisor.Monitoring.PromEx

  @check_timeout 10_000

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  ## Callbacks

  @impl true
  def init(_args) do
    send(self(), :check_metrics)
    {:ok, %{check_ref: make_ref()}}
  end

  @impl true
  def handle_info(:check_metrics, state) do
    Process.cancel_timer(state.check_ref)

    PromEx.do_cache_tenants_metrics()

    {:noreply, %{state | check_ref: check_metrics()}}
  end

  ## Internal functions

  defp check_metrics() do
    Process.send_after(
      self(),
      :check_metrics,
      @check_timeout
    )
  end
end
