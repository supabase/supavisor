defmodule Supavisor.CircuitBreaker do
  @moduledoc """
  Circuit breaker for pool operations.

  Uses two ETS tables:
  - `@blocks_table`: stores `{ets_key, blocked_until}` — the hot path for `check/2`.
    Tiny tuples, fast to copy.
  - `@windows_table`: stores `{ets_key, sliding_window}` — only touched on `record_failure/2`.
  """

  require Logger

  alias Supavisor.CircuitBreaker.SlidingWindow

  @windows_table Supavisor.CircuitBreaker.Windows
  @blocks_table Supavisor.CircuitBreaker.Blocks

  @config %{
    get_secrets: %{
      max_failures: 5,
      window_seconds: 600,
      block_seconds: 600,
      propagate?: false,
      explanation: "Failed to retrieve database credentials"
    },
    db_connection: %{
      max_failures: 100,
      window_seconds: 300,
      block_seconds: 600,
      propagate?: false,
      explanation: "Unable to establish connection to upstream database"
    },
    auth_error: %{
      max_failures: 10,
      window_seconds: 300,
      block_seconds: 600,
      propagate?: true,
      explanation: "Too many authentication errors"
    }
  }

  @doc """
  Initializes the circuit breaker ETS tables.
  Called by the application supervisor.
  """
  def init do
    :ets.new(@blocks_table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])

    :ets.new(@windows_table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])
  end

  @doc """
  Records a failure for a given key and operation.
  """
  @spec record_failure(term(), atom()) :: :ok
  def record_failure(key, operation) when is_atom(operation) do
    record_failures(key, operation, 1)
  end

  defp record_failures(key, operation, count) do
    threshold = Map.fetch!(@config, operation)
    ets_key = {key, operation}
    now = System.system_time(:second)

    # Skip if already blocked — no need to re-trip.
    case :ets.lookup(@blocks_table, ets_key) do
      [{^ets_key, blocked}] when blocked > now ->
        :ok

      _ ->
        sw = get_or_create_sw(ets_key, threshold.window_seconds, now)
        estimated = SlidingWindow.record(sw, now, count)

        if estimated >= threshold.max_failures do
          block_until = now + threshold.block_seconds
          :ets.insert(@blocks_table, {ets_key, block_until})

          Logger.warning(
            "Circuit breaker opened for key=#{inspect(key)} operation=#{operation} until=#{block_until}"
          )

          threshold.propagate? && open_global(key, operation, block_until)
        end

        :ok
    end
  end

  @doc """
  Checks if a circuit breaker is open for a given key and operation.
  Returns :ok if operation is allowed, {:error, :circuit_open, blocked_until} otherwise.
  """
  @spec check(term(), atom()) :: :ok | {:error, :circuit_open, integer()}
  def check(key, operation) when is_atom(operation) do
    ets_key = {key, operation}

    case :ets.lookup(@blocks_table, ets_key) do
      [] ->
        :ok

      [{^ets_key, blocked}] ->
        if blocked > System.system_time(:second) do
          {:error, :circuit_open, blocked}
        else
          :ets.delete_object(@blocks_table, {ets_key, blocked})
          :ok
        end
    end
  end

  @doc """
  Given the operation returns a list of {key, blocked_until} for which the circuit is opened.

  ## Examples

      iex> opened("tenant1", :auth_error)
      [{"tenant1", 1234567890}]

      iex> opened({"tenant1", "192.168.1.100"}, :auth_error)
      [{{"tenant1", "192.168.1.100"}, 1234567890}]

      iex> opened({"tenant1", :_}, :auth_error)
      [{{"tenant1", "192.168.1.100"}, 1234567890}, {"tenant1", "10.0.0.1"}, 1234567891}]
  """
  @spec opened(term(), atom()) :: [{term(), integer()}]
  def opened(key, operation) when is_atom(operation) do
    now = System.system_time(:second)

    :ets.match_object(@blocks_table, {{key, operation}, :_})
    |> Enum.reduce([], fn {{k, _op}, blocked}, acc ->
      if blocked > now do
        [{k, blocked} | acc]
      else
        acc
      end
    end)
  end

  @doc """
  Clears circuit breaker state for a key and operation.
  """
  @spec clear(term(), atom()) :: :ok
  def clear(key, operation) when is_atom(operation) do
    clear_local(key, operation)
    Map.fetch!(@config, operation).propagate? && clear_global(key, operation)
    :ok
  end

  @doc """
  Clears circuit breaker for a given key and operation on the current node.
  """
  @spec clear_local(term(), atom()) :: :ok
  def clear_local(key, operation) when is_atom(operation) do
    ets_key = {key, operation}
    :ets.delete(@blocks_table, ets_key)
    :ets.delete(@windows_table, ets_key)
    Logger.warning("Circuit breaker cleared for key=#{inspect(key)} operation=#{operation}")
    :ok
  end

  # Propagates the state clearing to all nodes in the cluster.
  defp clear_global(key, operation) do
    nodes = Node.list()

    nodes
    |> :erpc.multicall(__MODULE__, :clear_local, [key, operation], 10_000)
    |> then(&Enum.zip(nodes, &1))
    |> Enum.each(fn
      {node, {:ok, :ok}} ->
        Logger.debug(
          "Circuit breaker cleared for key=#{inspect(key)} operation=#{operation} node=#{node}"
        )

      {node, error} ->
        Logger.error(
          "Circuit breaker failed to clear for key=#{inspect(key)} operation=#{operation} node=#{node} error=#{inspect(error)}"
        )
    end)
  end

  @doc """
  Opens the circuit arbitrary for a given key and operation on the current node.
  """
  @spec open_local(term(), atom(), integer(), list(integer()) | nil) :: :ok
  def open_local(key, operation, blocked_until, _recent_failures \\ nil)
      when is_atom(operation) and is_integer(blocked_until) do
    ets_key = {key, operation}
    :ets.insert(@blocks_table, {ets_key, blocked_until})

    Logger.warning(
      "Circuit breaker opened for key=#{inspect(key)} operation=#{operation} until=#{blocked_until}"
    )

    :ok
  end

  # Propagates the circuit open to all nodes in the cluster.
  defp open_global(key, operation, blocked_until) do
    nodes = Node.list()

    nodes
    |> :erpc.multicall(__MODULE__, :open_local, [key, operation, blocked_until, nil], 10_000)
    |> then(&Enum.zip(nodes, &1))
    |> Enum.each(fn
      {node, {:ok, :ok}} ->
        Logger.debug(
          "Circuit breaker opened for key=#{inspect(key)} operation=#{operation} node=#{node}"
        )

      {node, error} ->
        Logger.error(
          "Circuit breaker failed to open for key=#{inspect(key)} operation=#{operation} node=#{node} error=#{inspect(error)}"
        )
    end)
  end

  @doc """
  Returns the user-facing explanation for a given operation.
  """
  @spec explanation(atom()) :: String.t()
  def explanation(operation) when is_atom(operation) do
    @config
    |> Map.fetch!(operation)
    |> Map.fetch!(:explanation)
  end

  @doc """
  Removes stale entries from the circuit breaker table.
  Called periodically by the Janitor process.
  """
  @spec cleanup_stale_entries() :: non_neg_integer()
  def cleanup_stale_entries do
    now = System.system_time(:second)

    entries = :ets.tab2list(@windows_table)

    deleted =
      Enum.reduce(entries, 0, fn {{key, operation} = ets_key, sw}, acc ->
        pre_delete_window = SlidingWindow.window_index(sw)
        op_config = Map.fetch!(@config, operation)
        op_stale_cutoff = div(now, op_config.window_seconds) - 2

        blocked =
          case :ets.lookup(@blocks_table, ets_key) do
            [{^ets_key, b}] -> b
            [] -> 0
          end

        not_blocked = blocked == 0 or blocked < now

        stale_window = pre_delete_window < op_stale_cutoff

        if not_blocked and stale_window do
          # Delete window first — record_failure callers that already hold the
          # atomics ref will still increment it, but new callers will create a
          # fresh window.
          :ets.delete(@windows_table, ets_key)

          # Only delete the exact block tuple we observed, not a fresh one that
          # a concurrent record_failure may have inserted after our lookup.
          if blocked > 0, do: :ets.delete_object(@blocks_table, {ets_key, blocked})

          # If window_index was rotated since our staleness check, a concurrent
          # record_failure was in-flight. Replay the estimated count so those
          # failures aren't lost.
          post_delete_window = SlidingWindow.window_index(sw)

          if post_delete_window != pre_delete_window do
            estimated = SlidingWindow.estimated_count(sw, now)

            if estimated > 0 do
              record_failures(key, operation, estimated)
            end
          end

          acc + 1
        else
          acc
        end
      end)

    if deleted > 0 do
      Logger.info("Circuit breaker cleaned up #{deleted} stale entries")
    end

    deleted
  end

  # Returns existing sw or creates a new one for the given ETS key.
  # Uses insert_new to handle concurrent creation races — only the first insert wins,
  # and the loser re-reads the winning ref.
  defp get_or_create_sw(ets_key, window_seconds, now, attempt \\ 0) do
    case :ets.lookup(@windows_table, ets_key) do
      [{^ets_key, sw}] ->
        sw

      [] ->
        sw = SlidingWindow.new(window_seconds, now)

        if :ets.insert_new(@windows_table, {ets_key, sw}) do
          sw
        else
          case :ets.lookup(@windows_table, ets_key) do
            [{^ets_key, existing_sw}] ->
              existing_sw

            [] ->
              get_or_create_sw(ets_key, window_seconds, now, attempt + 1)
          end
        end
    end
  end
end
