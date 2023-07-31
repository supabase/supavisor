defmodule Supavisor.Manager do
  @moduledoc false
  use GenServer, restart: :transient
  require Logger

  alias Supavisor.Protocol.Server
  alias Supavisor.Tenants

  @check_timeout 120_000

  def start_link(args) do
    name = {:via, Registry, {Supavisor.Registry.Tenants, {:manager, args.id}}}

    GenServer.start_link(__MODULE__, args, name: name)
  end

  @spec subscribe(pid, pid) :: {:ok, iodata() | []}
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
      user_alias: args.user_alias,
      parameter_status: [],
      wait_ps: [],
      default_parameter_status: args.default_parameter_status
    }

    Logger.metadata(project: args.tenant, user: args.user_alias)

    Registry.register(Supavisor.Registry.ManagerTables, {args.tenant, args.user_alias}, tid)

    {:ok, state}
  end

  @impl true
  def handle_call({:subscribe, pid}, _, %{tenant: tenant, user_alias: user_alias} = state) do
    Logger.info("Subscribing #{inspect(pid)} to tenant #{inspect({tenant, user_alias})}")
    :ets.insert(state.tid, {Process.monitor(pid), pid, now()})

    case state.parameter_status do
      [] ->
        {:reply, {:ok, []}, update_in(state.wait_ps, &[pid | &1])}

      ps ->
        {:reply, {:ok, ps}, state}
    end
  end

  def handle_call({:set_parameter_status, ps}, _, %{parameter_status: []} = state) do
    def_ps = state.default_parameter_status
    encoded_ps = Server.encode_parameter_status(ps)

    message =
      case check_parameter_status(ps, def_ps) do
        :ok ->
          encoded_ps

        {:error, reason} ->
          Logger.error("Parameter status error: #{inspect(reason)}")
          new_ps = %{server_version: ps["server_version"]}
          Tenants.update_tenant_ps(state.tenant, new_ps)
          :updated
      end

    for pid <- state.wait_ps do
      send(pid, {:parameter_status, message})
    end

    {:reply, :ok, %{state | parameter_status: encoded_ps, wait_ps: []}}
  end

  def handle_call({:set_parameter_status, _ps}, _, state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_info({:DOWN, ref, _, _, _}, state) do
    :ets.take(state.tid, ref)
    {:noreply, state}
  end

  def handle_info(:check_subscribers, %{tenant: tenant, user_alias: user_alias} = state) do
    Process.cancel_timer(state.check_ref)

    if :ets.info(state.tid, :size) == 0 do
      Logger.info("No subscribers for tenant #{inspect({tenant, user_alias})}, shutting down")
      Supavisor.stop(tenant, user_alias)
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

  @spec check_parameter_status(map, map) :: :ok | {:error, String.t()}
  defp check_parameter_status(ps, def_ps) do
    Enum.find_value(ps, :ok, fn {key, value} ->
      if def_ps[key] && def_ps[key] != value do
        {:error, "Parameter #{key} changed from #{def_ps[key]} to #{value}"}
      end
    end)
  end
end
