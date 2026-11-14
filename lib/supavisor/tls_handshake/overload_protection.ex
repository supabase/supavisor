defmodule Supavisor.TLSHandshake.OverloadProtection do
  @moduledoc """
  Queue control for each partition of `Supavisor.TLSHandshake.Supervisor`, as in
  DBConnection.ConnectionPool.

  A partition keeps the shortest wait of the starts it took during the current interval. If an
  interval ends with that above the target, even the fastest start waited too long, and during
  the next interval every start that waited more than twice the target is dropped. The first
  start of an interval is never dropped.
  """

  require Logger

  @target_key {__MODULE__, :target}
  @interval_key {__MODULE__, :interval}
  @queue_key {__MODULE__, :queue}

  @doc """
  Loads the target and the interval from the application env. Called at startup, and must be
  called again after that env changes.
  """
  @spec load_config() :: :ok
  def load_config do
    target_ms = Application.fetch_env!(:supavisor, :tls_handshake_queue_target_ms)
    interval_ms = Application.fetch_env!(:supavisor, :tls_handshake_queue_interval_ms)
    :persistent_term.put(@target_key, to_native(target_ms))
    :persistent_term.put(@interval_key, to_native(interval_ms))
  end

  @doc """
  Whether the partition should drop a start it takes at `now`, after it waited `delay` in the
  partition's queue. Both are in native time units. Must run in the partition, which keeps the
  state in its process dictionary.
  """
  # Port of DBConnection.ConnectionPool's dequeue/5.
  @spec drop?(integer(), integer()) :: boolean()
  def drop?(now, delay) do
    target = :persistent_term.get(@target_key)

    case Process.get(@queue_key) do
      {next, min_delay, slow?} when now >= next ->
        overloaded? = min_delay > target
        maybe_log_change(slow?, overloaded?, min_delay, target)
        queue_put(now, delay, overloaded?)
        false

      nil ->
        queue_put(now, delay, false)
        false

      {_next, _min_delay, true} when delay > target * 2 ->
        true

      {next, min_delay, slow?} when delay < min_delay ->
        Process.put(@queue_key, {next, delay, slow?})
        false

      _ ->
        false
    end
  end

  defp maybe_log_change(previous, new, _min_delay, _target) when new == previous, do: :ok

  defp maybe_log_change(_previous, overloaded?, min_delay, target) do
    {level, status} = if overloaded?, do: {:warning, "overloaded"}, else: {:info, "recovered"}

    Logger.log(
      level,
      "TLS handshake queue #{status}: shortest wait was #{to_ms(min_delay)}ms, target is #{to_ms(target)}ms"
    )
  end

  defp queue_put(now, delay, slow?) do
    Process.put(@queue_key, {now + :persistent_term.get(@interval_key), delay, slow?})
  end

  defp to_ms(native), do: System.convert_time_unit(native, :native, :millisecond)
  defp to_native(ms), do: System.convert_time_unit(ms, :millisecond, :native)
end
