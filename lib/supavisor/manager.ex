defmodule Supavisor.Manager do
  @moduledoc false
  use GenServer, restart: :transient
  require Logger

  alias Supavisor.Protocol.Server

  @check_timeout 120_000

  def start_link(args) do
    name = {:via, Registry, {Supavisor.Registry.Tenants, {:manager, args.tenant}}}
    GenServer.start_link(__MODULE__, args, name: name)
  end

  def subscribe(manager, pid) do
    GenServer.call(manager, {:subscribe, pid})
  end

  @spec set_parameter_status(pid, map) :: :ok
  def set_parameter_status(manager, ps) do
    GenServer.call(manager, {:set_parameter_status, ps})
  end

  @spec get_parameter_status(pid) :: iodata() | []
  def get_parameter_status(manager) do
    GenServer.call(manager, :get_parameter_status)
  end

  ## Callbacks

  @impl true
  def init(args) do
    tid = :ets.new(__MODULE__, [:public])

    state = %{
      check_ref: check_subscribers(),
      tid: tid,
      tenant: args.tenant,
      parameter_status: []
    }

    Registry.register(Supavisor.Registry.ManagerTables, args.tenant, tid)

    {:ok, state}
  end

  @impl true
  def handle_call({:subscribe, pid}, _, state) do
    Logger.info("Subscribing #{inspect(pid)} to tenant #{state.tenant}")
    :ets.insert(state.tid, {Process.monitor(pid), pid, now()})
    {:reply, :ok, state}
  end

  def handle_call({:set_parameter_status, ps}, _, %{parameter_status: []} = state) do
    encoded_ps = Server.encode_parameter_status(ps)
    {:reply, :ok, %{state | parameter_status: encoded_ps}}
  end

  def handle_call({:set_parameter_status, _ps}, _, state) do
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
      Supavisor.stop(state.tenant)
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
