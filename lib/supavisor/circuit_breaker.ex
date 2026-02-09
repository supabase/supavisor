defmodule Supavisor.CircuitBreaker do
  @moduledoc """
  Simple ETS-based circuit breaker for pool operations.

  Tracks failures per tenant and blocks operations when thresholds are exceeded.
  """

  require Logger

  @table __MODULE__

  @thresholds %{
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

  For the :auth_error, it the circuit is opened, it is opened across all the nodes
  in the cluster.
  """
  @spec record_failure(term(), atom()) :: :ok
  def record_failure(key, operation) when is_atom(operation) do
    now = System.system_time(:second)
    ets_key = {key, operation}

    case :ets.lookup(@table, ets_key) do
      [] ->
        :ets.insert(@table, {ets_key, %{failures: [now], blocked_until: nil}})

      [{^ets_key, state}] ->
        threshold = Map.fetch!(@thresholds, operation)
        window_start = now - threshold.window_seconds

        recent_failures = Enum.filter([now | state.failures], &(&1 >= window_start))

        if length(recent_failures) >= threshold.max_failures do
          block_until = now + threshold.block_seconds
          open_local(key, operation, block_until, recent_failures)
          threshold.propagate? && open_global(key, operation, block_until)
        else
          :ets.insert(@table, {ets_key, %{state | failures: recent_failures}})
        end
    end

    :ok
  end

  @doc """
  Checks if a circuit breaker is open for a given key and operation.
  Returns :ok if operation is allowed, {:error, :circuit_open, blocked_until} otherwise.
  """
  @spec check(term(), atom()) :: :ok | {:error, :circuit_open, integer()}
  def check(key, operation) when is_atom(operation) do
    now = System.system_time(:second)
    ets_key = {key, operation}

    case :ets.lookup(@table, ets_key) do
      [] ->
        :ok

      [{^ets_key, %{blocked_until: nil}}] ->
        :ok

      [{^ets_key, %{blocked_until: blocked_until}}] when blocked_until > now ->
        {:error, :circuit_open, blocked_until}

      [{^ets_key, state}] ->
        :ets.insert(@table, {ets_key, %{state | blocked_until: nil}})
        :ok
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

    :ets.select(@table, [
      {{{key, operation}, %{blocked_until: :"$1"}},
       [{:andalso, {:is_integer, :"$1"}, {:>, :"$1", now}}], [:"$_"]}
    ])
    |> Enum.map(fn {{key, _operation}, %{blocked_until: blocked_until}} ->
      {key, blocked_until}
    end)
  end

  @doc """
  Clears circuit breaker state for a key and operation.
  """
  @spec clear(term(), atom()) :: :ok
  def clear(key, operation) when is_atom(operation) do
    clear_local(key, operation)
    Map.fetch!(@thresholds, operation).propagate? && clear_global(key, operation)
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
  def open_local(key, operation, blocked_until, recent_failures \\ nil)
      when is_atom(operation) and is_integer(blocked_until) and
             (is_list(recent_failures) or is_nil(recent_failures)) do
    ets_key = {key, operation}

    case :ets.lookup(@table, ets_key) do
      [] ->
        :ets.insert(
          @table,
          {ets_key, %{failures: recent_failures || [], blocked_until: blocked_until}}
        )

      [{^ets_key, state}] ->
        :ets.insert(
          @table,
          {ets_key,
           %{
             state
             | failures: recent_failures || state.failures,
               blocked_until: blocked_until
           }}
        )
    end

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
    @thresholds
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
    max_window = @thresholds |> Map.values() |> Enum.map(& &1.window_seconds) |> Enum.max()
    cutoff = now - max_window * 2

    match_spec = [
      {{{:"$1", :"$2"}, %{failures: :"$3", blocked_until: :"$4"}}, [],
       [{{:"$1", :"$2", :"$3", :"$4"}}]}
    ]

    entries = :ets.select(@table, match_spec)

    deleted =
      Enum.reduce(entries, 0, fn {tenant, operation, failures, blocked_until}, acc ->
        latest_failure = List.first(failures) || 0
        expired_block = blocked_until && blocked_until < now

        if latest_failure < cutoff and (is_nil(blocked_until) or expired_block) do
          :ets.delete(@table, {tenant, operation})
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
end
