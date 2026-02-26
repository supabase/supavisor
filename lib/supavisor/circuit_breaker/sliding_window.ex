defmodule Supavisor.CircuitBreaker.SlidingWindow do
  @moduledoc """
  Atomics-based sliding window counter with blocking support.

  Maintains an approximate count of events over a time window using two
  adjacent windows and linear interpolation. All operations are O(1)
  and lock-free via `:atomics`.

  ### Layout (3 unsigned atomics slots)

  - Slot 1: packed counts — high 32 bits = prev count, low 32 bits = current count
  - Slot 2: window index (`div(now, window_seconds)`)
  - Slot 3: blocked_until (unix timestamp, 0 = not blocked)

  ### How it works

  Time is divided into fixed-size windows (`window_seconds`). Each window is
  identified by its index: `div(now, window_seconds)`. We keep counts for the
  current and previous windows, and estimate the sliding total using linear
  interpolation between them.

  Both counts are packed into a single 64-bit atomic (prev in the high 32 bits,
  current in the low 32 bits). This lets us read a consistent snapshot of both
  counts with a single `get`, and update them atomically via CAS loops.

  #### Recording events (`record/3`)

  1. **Rotate** if the window index has advanced (see below).
  2. **Increment** current count: `:atomics.add(ref, @counts, 1)`. Since
     current is in the low 32 bits, a plain `add` of 1 does the right thing.
  3. **Estimate** the sliding count from a single atomic read.

  #### Rotation

  When the window index advances, one process wins a CAS on the `window_index`
  slot and becomes responsible for transforming the packed counts:

  - **Adjacent window** (index advanced by 1): CAS loop shifts current into
    prev and zeros current (`shift_current_to_prev/1`).
  - **Stale window** (index advanced by 2+): CAS loop zeros prev while
    preserving current (`reset_counts/1`).

  Losers of the `window_index` CAS skip rotation and proceed to increment.

  #### Estimated count

  A single `get` of the packed counts slot yields a consistent {prev, current}
  pair. The estimate is:

      prev * ((window_seconds - elapsed) / window_seconds) + current

  where `elapsed = rem(now, window_seconds)`.

  ### Known race

  There is a narrow race between the `window_index` CAS and the `@counts`
  CAS loop during rotation. A concurrent `add` may be misattributed to
  the wrong window (e.g. shifted into prev), but counts are never lost.
  """

  import Bitwise

  @counts 1
  @window_index 2
  @blocked_until 3

  @low_mask 0xFFFFFFFF

  @doc """
  Creates a new sliding window reference.
  """
  @spec new() :: reference()
  def new do
    :atomics.new(3, signed: false)
  end

  @doc """
  Records one event, rotating the window if needed.
  Returns the estimated count after the increment.
  """
  @spec record(reference(), integer(), pos_integer()) :: non_neg_integer()
  def record(ref, now, window_seconds) do
    current_window = div(now, window_seconds)
    rotate(ref, current_window)
    :atomics.add(ref, @counts, 1)
    estimated_count(ref, now, window_seconds)
  end

  @doc """
  Returns the blocked_until timestamp (0 means not blocked).
  """
  @spec blocked_until(reference()) :: non_neg_integer()
  def blocked_until(ref) do
    :atomics.get(ref, @blocked_until)
  end

  @doc """
  Sets the blocked_until timestamp.
  """
  @spec block_until(reference(), non_neg_integer()) :: :ok
  def block_until(ref, timestamp) do
    :atomics.put(ref, @blocked_until, timestamp)
  end

  @doc """
  Clears the blocked state (sets blocked_until to 0).
  """
  @spec unblock(reference()) :: :ok
  def unblock(ref) do
    :atomics.put(ref, @blocked_until, 0)
  end

  @doc """
  Returns the current window index stored in the ref.
  """
  @spec window_index(reference()) :: non_neg_integer()
  def window_index(ref) do
    :atomics.get(ref, @window_index)
  end

  # Rotates the sliding window if the current window index has advanced.
  #
  # Uses compare_exchange on the window_index slot so that only one process
  # wins the rotation. Losers see the compare_exchange failing
  # (the winner already set window_index to current_window) and just
  # proceed to increment current_count.
  defp rotate(ref, current_window) do
    stored_window = :atomics.get(ref, @window_index)

    cond do
      stored_window == current_window ->
        :ok

      stored_window == current_window - 1 ->
        case :atomics.compare_exchange(ref, @window_index, stored_window, current_window) do
          :ok ->
            # We won the rotation — shift current into prev, reset current.
            shift_current_to_prev(ref)

          _ ->
            # Another process already rotated — nothing to do.
            :ok
        end

      true ->
        case :atomics.compare_exchange(ref, @window_index, stored_window, current_window) do
          :ok ->
            # We won — stale window, reset prev and zero current via CAS loop
            # to avoid wiping concurrent increments.
            reset_counts(ref)

          _ ->
            :ok
        end
    end
  end

  # CAS loop to atomically shift current count into prev and zero current.
  # Retries if a concurrent increment lands between read and CAS.
  defp shift_current_to_prev(ref) do
    old = :atomics.get(ref, @counts)
    current = old &&& @low_mask
    new_packed = current <<< 32

    case :atomics.compare_exchange(ref, @counts, old, new_packed) do
      :ok -> :ok
      _ -> shift_current_to_prev(ref)
    end
  end

  # CAS loop to zero prev while preserving concurrent increments to current.
  defp reset_counts(ref) do
    old = :atomics.get(ref, @counts)
    new_packed = old &&& @low_mask

    case :atomics.compare_exchange(ref, @counts, old, new_packed) do
      :ok -> :ok
      _ -> reset_counts(ref)
    end
  end

  defp estimated_count(ref, now, window_seconds) do
    packed = :atomics.get(ref, @counts)
    current = packed &&& @low_mask
    prev = packed >>> 32
    elapsed = rem(now, window_seconds)
    weight = (window_seconds - elapsed) / window_seconds
    trunc(prev * weight + current)
  end
end
