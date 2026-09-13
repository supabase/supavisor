defmodule Supavisor.ConnectionListener do
  use GenServer

  require Logger

  @name __MODULE__

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, nil, Keyword.put_new(opts, :name, @name))
  end

  @impl true
  def init(nil) do
    Process.flag(:trap_exit, true)
    {:ok, %{monitoring: %{}}}
  end

  @impl true
  def handle_info({:connected, pid, connect_start_time}, state) do
    {start_time, state} =
      case Map.get(state.monitoring, pid) do
        nil ->
          ref = Process.monitor(pid)
          {connect_start_time, put_in(state, [:monitoring, pid], {ref, nil})}

        {ref, disconnect_time} ->
          {disconnect_time || connect_start_time, put_in(state, [:monitoring, pid], {ref, nil})}
      end

    connect_duration = System.monotonic_time() - start_time

    :telemetry.execute(
      [:supavisor, :auth_query, :connection, :stop],
      %{duration: connect_duration}
    )

    {:noreply, state}
  end

  def handle_info({:disconnected, pid, _}, state) do
    case Map.get(state.monitoring, pid) do
      nil ->
        {:noreply, state}

      {_ref, prev_disconnect_ts} when not is_nil(prev_disconnect_ts) ->
        Logger.warning("Duplicate disconnected event for pid #{inspect(pid)})")
        {:noreply, state}

      {ref, nil} ->
        :telemetry.execute(
          [:supavisor, :auth_query, :disconnection],
          %{count: 1}
        )

        {:noreply, put_in(state, [:monitoring, pid], {ref, System.monotonic_time()})}
    end
  end

  def handle_info({:disconnected, pid}, state) do
    handle_info({:disconnected, pid, nil}, state)
  end

  # we only get monitor message if we have seen the connected event first
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    case Map.pop(state.monitoring, pid) do
      {nil, _} ->
        {:noreply, state}

      {{_ref, prev_disconnect_ts}, monitoring} when not is_nil(prev_disconnect_ts) ->
        Logger.warning(
          "Duplicate disconnected event for pid #{inspect(pid)} (#{inspect(reason)})"
        )

        {:noreply, %{state | monitoring: monitoring}}

      {{ref, nil}, monitoring} ->
        Process.demonitor(ref, [:flush])

        :telemetry.execute(
          [:supavisor, :auth_query, :disconnection],
          %{count: 1},
          (reason == :normal && %{}) || %{kind: :exit, reason: reason}
        )

        {:noreply, %{state | monitoring: monitoring}}
    end
  end
end
