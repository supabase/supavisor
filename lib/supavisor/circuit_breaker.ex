defmodule Supavisor.CircuitBreaker do
  @moduledoc """
  Atomics-based circuit breaker for pool operations.

  Each `{key, operation}` maps to a `SlidingWindow` ref stored in an ETS table.
  Uses a sliding window approximation for failure counting — O(1) writes,
  O(1) reads, no race conditions on counting.
  """

  require Logger

  alias Supavisor.CircuitBreaker.SlidingWindow

  @table __MODULE__

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
  Initializes the circuit breaker ETS table.
  Called by the application supervisor.
  """
  def init do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
  end

  @doc """
  Records a failure for a given key and operation.
  """
  @spec record_failure(term(), atom()) :: :ok
  def record_failure(key, operation) when is_atom(operation) do
    threshold = Map.fetch!(@config, operation)
    ref = get_or_create_ref({key, operation})
    now = System.system_time(:second)

    estimated = SlidingWindow.record(ref, now, threshold.window_seconds)

    if estimated >= threshold.max_failures do
      block_until = now + threshold.block_seconds
      SlidingWindow.block_until(ref, block_until)

      Logger.warning(
        "Circuit breaker opened for key=#{inspect(key)} operation=#{operation} until=#{block_until}"
      )

      threshold.propagate? && open_global(key, operation, block_until)
    end

    :ok
  end

  @doc """
  Checks if a circuit breaker is open for a given key and operation.
  Returns :ok if operation is allowed, {:error, :circuit_open, blocked_until} otherwise.
  """
  @spec check(term(), atom()) :: :ok | {:error, :circuit_open, integer()}
  def check(key, operation) when is_atom(operation) do
    ets_key = {key, operation}

    case :ets.lookup(@table, ets_key) do
      [] ->
        :ok

      [{^ets_key, ref}] ->
        blocked = SlidingWindow.blocked_until(ref)

        cond do
          blocked == 0 ->
            :ok

          blocked > System.system_time(:second) ->
            {:error, :circuit_open, blocked}

          true ->
            SlidingWindow.unblock(ref)
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
      [{{"tenant1", "192.168.1.100"}, 1234567890}, {{"tenant1", "10.0.0.1"}, 1234567891}]
  """
  @spec opened(term(), atom()) :: [{term(), integer()}]
  def opened(key, operation) when is_atom(operation) do
    now = System.system_time(:second)

    :ets.match_object(@table, {{key, operation}, :_})
    |> Enum.reduce([], fn {{k, _op}, ref}, acc ->
      blocked = SlidingWindow.blocked_until(ref)

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
    :ets.delete(@table, {key, operation})
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
    ref = get_or_create_ref({key, operation})
    SlidingWindow.block_until(ref, blocked_until)

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
    max_window = @config |> Map.values() |> Enum.map(& &1.window_seconds) |> Enum.max()
    stale_window_cutoff = div(now, max_window) - 2

    entries = :ets.tab2list(@table)

    deleted =
      Enum.reduce(entries, 0, fn {{_key, operation} = ets_key, ref}, acc ->
        blocked = SlidingWindow.blocked_until(ref)
        window = SlidingWindow.window_index(ref)
        op_config = Map.fetch!(@config, operation)
        op_stale_cutoff = div(now, op_config.window_seconds) - 2

        not_blocked = blocked == 0 or blocked < now
        stale_window = window < op_stale_cutoff and window < stale_window_cutoff

        if not_blocked and stale_window do
          :ets.delete(@table, ets_key)
          acc + 1
        else
          acc
        end
      end)

    if deleted > 0 do
      Logger.debug("Circuit breaker cleaned up #{deleted} stale entries")
    end

    deleted
  end

  # Returns existing ref or creates a new one for the given ETS key.
  # Uses insert_new to handle concurrent creation races — only the first insert wins,
  # and the loser re-reads the winning ref.
  defp get_or_create_ref(ets_key) do
    case :ets.lookup(@table, ets_key) do
      [{^ets_key, ref}] ->
        ref

      [] ->
        ref = SlidingWindow.new()

        if :ets.insert_new(@table, {ets_key, ref}) do
          ref
        else
          [{^ets_key, existing_ref}] = :ets.lookup(@table, ets_key)
          existing_ref
        end
    end
  end
end
