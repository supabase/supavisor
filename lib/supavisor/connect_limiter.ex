defmodule Supavisor.ConnectLimiter do
  @moduledoc """
  Limits the number of concurrent database connection attempts within a single
  tenant's pool.

  DbHandlers request a slot asynchronously via `request_slot/1`. If a slot is
  available, the caller is immediately notified. Otherwise, the request is
  queued and the caller is notified when a slot frees up.

  Each slot holder is monitored. If the holder dies without releasing, the slot
  is automatically reclaimed.
  """

  use GenServer

  require Supavisor

  @max_concurrency 10

  def start_link(opts) do
    id = Keyword.fetch!(opts, :id)
    GenServer.start_link(__MODULE__, @max_concurrency, name: name(id))
  end

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  @doc """
  Requests a connect slot for the calling process.

  If a slot is available, sends `{:connect_slot_granted, ref}` immediately.
  Otherwise, the caller is queued and notified when a slot becomes available.

  Returns a reference that must be passed to `release_slot/2`.
  """
  @spec request_slot(Supavisor.id()) :: reference()
  def request_slot(id) do
    ref = make_ref()
    GenServer.cast(name(id), {:request, self(), ref})
    ref
  end

  @doc """
  Releases a connect slot previously granted to the calling process.
  """
  @spec release_slot(Supavisor.id(), reference()) :: :ok
  def release_slot(id, ref) do
    GenServer.cast(name(id), {:release, self(), ref})
  end

  defp name(id) do
    {:via, Registry, {Supavisor.Registry.Tenants, {:connect_limiter, id}}}
  end

  # Server

  @impl true
  def init(max_concurrency) do
    {:ok,
     %{
       max: max_concurrency,
       active: %{},
       queue: :queue.new()
     }}
  end

  @impl true
  def handle_cast({:request, pid, ref}, state) do
    if map_size(state.active) < state.max do
      {:noreply, grant(state, pid, ref)}
    else
      {:noreply, %{state | queue: :queue.in({pid, ref}, state.queue)}}
    end
  end

  def handle_cast({:release, pid, ref}, state) do
    {:noreply, do_release(state, pid, ref)}
  end

  @impl true
  def handle_info({:DOWN, mon_ref, :process, pid, _reason}, state) do
    case Map.pop(state.active, pid) do
      {{^mon_ref, _ref}, new_active} ->
        {:noreply, grant_next(%{state | active: new_active})}

      {nil, _} ->
        {:noreply, drop_from_queue(state, pid)}
    end
  end

  defp grant(state, pid, ref) do
    mon_ref = Process.monitor(pid)
    send(pid, {:connect_slot_granted, ref})
    %{state | active: Map.put(state.active, pid, {mon_ref, ref})}
  end

  defp do_release(state, pid, ref) do
    case Map.get(state.active, pid) do
      {mon_ref, ^ref} ->
        Process.demonitor(mon_ref, [:flush])
        grant_next(%{state | active: Map.delete(state.active, pid)})

      _ ->
        state
    end
  end

  defp grant_next(state) do
    case dequeue_alive(state.queue) do
      {:ok, {pid, ref}, rest} ->
        grant(%{state | queue: rest}, pid, ref)

      :empty ->
        state
    end
  end

  defp dequeue_alive(queue) do
    case :queue.out(queue) do
      {{:value, {pid, _ref} = item}, rest} ->
        if Process.alive?(pid) do
          {:ok, item, rest}
        else
          dequeue_alive(rest)
        end

      {:empty, _} ->
        :empty
    end
  end

  defp drop_from_queue(state, pid) do
    new_queue = :queue.filter(fn {p, _} -> p != pid end, state.queue)
    %{state | queue: new_queue}
  end
end
