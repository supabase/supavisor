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

  #### Recording events (`record/2`)

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

  @enforce_keys [:ref, :window_seconds]
  defstruct [:ref, :window_seconds]

  @type t :: %__MODULE__{ref: reference(), window_seconds: pos_integer()}

  @doc """
  Creates a new sliding window with the given window size in seconds.
  """
  @spec new(pos_integer()) :: t()
  def new(window_seconds) do
    %__MODULE__{
      ref: :atomics.new(3, signed: false),
      window_seconds: window_seconds
    }
  end

  @doc """
  Records one event, rotating the window if needed.
  Returns the estimated count after the increment.
  """
  @spec record(t(), integer()) :: non_neg_integer()
  def record(%__MODULE__{ref: ref, window_seconds: window_seconds}, now) do
    current_window = div(now, window_seconds)
    rotate(ref, current_window)
    :atomics.add(ref, @counts, 1)
    estimated_count(ref, now, window_seconds)
  end

  @doc """
  Returns the blocked_until timestamp (0 means not blocked).
  """
  @spec blocked_until(t()) :: non_neg_integer()
  def blocked_until(%__MODULE__{ref: ref}) do
    :atomics.get(ref, @blocked_until)
  end

  @doc """
  Sets the blocked_until timestamp.
  """
  @spec block_until(t(), non_neg_integer()) :: :ok
  def block_until(%__MODULE__{ref: ref}, timestamp) do
    :atomics.put(ref, @blocked_until, timestamp)
  end

  @doc """
  Clears the blocked state (sets blocked_until to 0).
  """
  @spec unblock(t()) :: :ok
  def unblock(%__MODULE__{ref: ref}) do
    :atomics.put(ref, @blocked_until, 0)
  end

  @doc """
  Returns the current window index stored in the ref.
  """
  @spec window_index(t()) :: non_neg_integer()
  def window_index(%__MODULE__{ref: ref}) do
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
      stored_window >= current_window ->
        # Same window or clock went backwards — don't rotate.
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
            # We won — stale window, reset both prev and current via CAS loop.
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

  # Zeros both prev and current. Used when the window advanced by 2+,
  # meaning both counts are from irrelevant windows.
  #
  # A concurrent add from a process that already passed rotate can land
  # just before the put and get wiped, meaning some event may be lost.
  defp reset_counts(ref) do
    :atomics.put(ref, @counts, 0)
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
