defmodule Supavisor.Logger.BurstDropCounter do
  @moduledoc """
  Estimates how many log events the `:default` logger handler's burst-limit
  overload protection drops.

  OTP gives no notification when a burst-limit drop happens and keeps no
  accessible running total, so this mirrors the same window/threshold
  independently: a `:logger` handler filter tallies every event reaching
  `:default`, and on each tick (matching `burst_limit_window_time`) whatever
  exceeds `burst_limit_max_count` is reported as the estimated drop count for
  that window via `:telemetry`.
  """

  use GenServer

  @event [:supavisor, :logger, :burst_limit, :dropped]

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, Keyword.put_new(opts, :filter_id, name), name: name)
  end

  @impl true
  def init(opts) do
    handler_id = Keyword.get(opts, :handler_id, :default)
    filter_id = Keyword.get(opts, :filter_id, __MODULE__)
    ref = :counters.new(1, [:atomics])

    if Keyword.get(opts, :install_filter?, true) and burst_limit_enable?() do
      # remove our stale filter if it exists and install a new one
      :logger.remove_handler_filter(handler_id, filter_id)
      :ok = :logger.add_handler_filter(handler_id, filter_id, {&__MODULE__.count/2, ref})
    end

    schedule_tick()

    {:ok, %{ref: ref, handler_id: handler_id, filter_id: filter_id}}
  end

  @impl true
  def terminate(_reason, %{handler_id: handler_id, filter_id: filter_id}) do
    :logger.remove_handler_filter(handler_id, filter_id)
    :ok
  end

  @doc """
  The `:logger` handler filter callback (see `:logger.add_handler_filter/3`).
  Always returns `log_event` unchanged — its only job is to count, never to
  alter what gets logged.
  """
  def count(log_event, ref) do
    :counters.add(ref, 1, 1)
    log_event
  end

  @impl true
  def handle_info(:tick, %{ref: ref} = state) do
    count = :counters.get(ref, 1)
    # Subtract exactly what was read, not a blind reset to 0, so a `count/2`
    # increment landing between the read above and this reset isn't lost —
    # it just rolls into the next window.
    :counters.sub(ref, 1, count)

    dropped = max(count - max_count(), 0)

    if dropped > 0 do
      :telemetry.execute(@event, %{count: dropped}, %{})
    end

    schedule_tick()
    {:noreply, state}
  end

  defp schedule_tick, do: Process.send_after(self(), :tick, window_time_ms())

  defp burst_limit_enable?, do: Application.fetch_env!(:supavisor, :logger_burst_limit_enable)
  defp max_count, do: Application.fetch_env!(:supavisor, :logger_burst_limit_max_count)
  defp window_time_ms, do: Application.fetch_env!(:supavisor, :logger_burst_limit_window_time)
end
