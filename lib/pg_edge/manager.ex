defmodule PgEdge.Manager do
  @moduledoc false
  use GenServer, restart: :transient
  require Logger

  @check_timeout 120_000

  def start_link(opts) do
    name = {:via, :syn, {:manager, opts.tenant}}
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def subscribe(tenant) do
    :syn.whereis_name({:manager, tenant})
    |> GenServer.call(:subscribe)
  end

  ## Callbacks

  @impl true
  @spec init(atom | %{:tenant => any, optional(any) => any}) ::
          {:ok, %{check_ref: reference, tenant: any, tid: atom | :ets.tid()}}
  def init(args) do
    state = %{
      check_ref: check_subscribers(),
      tid: :ets.new(__MODULE__, [:public]),
      tenant: args.tenant
    }

    {:ok, state}
  end

  @impl true
  def handle_call(:subscribe, {pid, _}, state) do
    Logger.info("Subscribing #{inspect(pid)} to tenant #{state.tenant}")
    :ets.insert(state.tid, {Process.monitor(pid), pid, now()})
    {:reply, :ok, state}
  end

  @impl true
  def handle_info({:DOWN, ref, _, _, _}, state) do
    :ets.take(state.tid, ref)
    {:noreply, state}
  end

  def handle_info(:check_subscribers, state) do
    Process.cancel_timer(state.check_ref)

    if :ets.info(state.tid, :size) == 0 do
      Logger.info("No subscribers for tenant #{state.tenant}, shutting down")
      PgEdge.stop_pool(state.tenant)
      {:stop, :normal}
    else
      {:noreply, %{state | check_ref: check_subscribers()}}
    end
  end

  ## Internal functions

  defp check_subscribers() do
    Process.send_after(
      self(),
      :check_subscribers,
      @check_timeout
    )
  end

  defp now() do
    System.system_time(:second)
  end
end
