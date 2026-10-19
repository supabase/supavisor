defmodule Supavisor.ConnectGate do
  @lease_ms 5_000

  @moduledoc """
  Lets one DbHandler of a tenant tree at a time connect and authenticate to the
  database.

  A DbHandler acquires a lease before connecting and releases it once
  authentication succeeds or fails. The others wait in arrival order. A lease
  expires after #{@lease_ms}ms: its holder carries on, and the next DbHandler in
  line gets a lease.

  The gate only starts when the tenant's `"connect_gate"` feature flag is
  enabled, and DbHandlers only use it while the flag is enabled.
  """

  use GenServer

  require Logger
  require Supavisor

  alias Supavisor.FeatureFlag
  alias Supavisor.Manager

  @type lease :: {pid(), reference()}

  def start_link(args) do
    name = {:via, Registry, {Supavisor.Registry.Tenants, {:connect_gate, args.id}}}
    GenServer.start_link(__MODULE__, args, name: name)
  end

  @doc """
  Puts the caller in line for a lease.

  The gate sends `{:connect_lease, ref}` to the caller once the lease is
  granted. The caller monitors the gate with `ref`, so it gets
  `{:DOWN, ref, :process, _, _}` instead if the gate goes down first.
  """
  @spec acquire(Supavisor.id()) :: {:ok, lease()} | {:error, :not_running}
  def acquire(id) do
    case Registry.lookup(Supavisor.Registry.Tenants, {:connect_gate, id}) do
      [{gate, _}] ->
        ref = Process.monitor(gate)
        GenServer.cast(gate, {:acquire, self(), ref})
        {:ok, {gate, ref}}

      [] ->
        {:error, :not_running}
    end
  end

  @doc """
  Releases a lease. Releasing an expired lease does nothing.
  """
  @spec release(lease()) :: :ok
  def release({gate, ref}) do
    Process.demonitor(ref, [:flush])
    GenServer.cast(gate, {:release, ref})
  end

  @impl true
  def init(args) do
    %{tenant_feature_flags: feature_flags} = Manager.get_config(args.id)

    if FeatureFlag.enabled?(feature_flags, "connect_gate") do
      Supavisor.id(type: type, tenant: tenant, user: user, db: db_name) = args.id
      Logger.metadata(project: tenant, user: user, type: type, db_name: db_name)

      {:ok, %{holder: nil, waiting: :queue.new()}}
    else
      :ignore
    end
  end

  @impl true
  def handle_cast({:acquire, pid, ref}, state) do
    monitor = Process.monitor(pid)
    waiting = :queue.in({ref, pid, monitor}, state.waiting)
    {:noreply, grant_next(%{state | waiting: waiting})}
  end

  def handle_cast({:release, ref}, %{holder: {ref, _pid, monitor}} = state) do
    Process.demonitor(monitor, [:flush])
    {:noreply, grant_next(%{state | holder: nil})}
  end

  def handle_cast({:release, _ref}, state), do: {:noreply, state}

  @impl true
  def handle_info({:lease_expired, ref}, %{holder: {ref, _pid, monitor}} = state) do
    Logger.warning(
      "connect lease expired after #{@lease_ms}ms, letting the next server connection start"
    )

    Process.demonitor(monitor, [:flush])
    {:noreply, grant_next(%{state | holder: nil})}
  end

  def handle_info({:lease_expired, _ref}, state), do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, %{holder: {_, _, monitor}} = state) do
    {:noreply, grant_next(%{state | holder: nil})}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    waiting = :queue.filter(fn {_ref, _pid, m} -> m != monitor end, state.waiting)
    {:noreply, %{state | waiting: waiting}}
  end

  defp grant_next(%{holder: nil} = state) do
    case :queue.out(state.waiting) do
      {{:value, {ref, pid, _monitor} = holder}, waiting} ->
        send(pid, {:connect_lease, ref})
        Process.send_after(self(), {:lease_expired, ref}, @lease_ms)
        %{state | holder: holder, waiting: waiting}

      {:empty, _} ->
        state
    end
  end

  defp grant_next(state), do: state
end
