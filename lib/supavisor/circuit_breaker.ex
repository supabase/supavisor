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
      explanation: "Failed to retrieve database credentials"
    },
    db_connection: %{
      max_failures: 100,
      window_seconds: 300,
      block_seconds: 600,
      explanation: "Unable to establish connection to upstream database"
    },
    auth_error: %{
      max_failures: 10,
      window_seconds: 300,
      block_seconds: 600,
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

        blocked_until =
          if length(recent_failures) >= threshold.max_failures do
            block_until = now + threshold.block_seconds

            Logger.warning(
              "Circuit breaker opened for key=#{inspect(key)} operation=#{operation} until=#{block_until}"
            )

            maybe_open_globally(key, operation, block_until)

            block_until
          else
            state.blocked_until
          end

        :ets.insert(@table, {ets_key, %{failures: recent_failures, blocked_until: blocked_until}})
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

  For :auth_error operation clears the state on all the cluster nodes.
  """
  @spec clear(term(), atom()) :: :ok
  def clear(key, operation) when is_atom(operation) do
    do_clear(key, operation)
    maybe_clear_globally(key, operation)
    Logger.warning("Circuit breaker cleared for key=#{inspect(key)} operation=#{operation}")
    :ok
  end

  @doc false
  # public function for remote clearing
  def do_clear(key, operation) do
    :ets.delete(@table, {key, operation})
    :ok
  end

  # Clears circuit breaker state globally for :auth_error operation.
  # Propagates the clear operation to all nodes in the cluster.
  defp maybe_clear_globally(key, :auth_error = operation) do
    nodes = Node.list()

    nodes
    |> :erpc.multicall(__MODULE__, :do_clear, [key, operation], 10_000)
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

  defp maybe_clear_globally(_, _), do: :ok

  @doc """
  Open the circuit arbitrary for a given key and operation.

  This directly sets blocked_until without counting failures. Used for
  propagating the opened circuit state across the cluster.
  """
  @spec open(term(), atom(), integer()) :: :ok
  def open(key, operation, blocked_until)
      when is_atom(operation) and is_integer(blocked_until) do
    ets_key = {key, operation}

    case :ets.lookup(@table, ets_key) do
      [] ->
        :ets.insert(@table, {ets_key, %{failures: [], blocked_until: blocked_until}})

      [{^ets_key, state}] ->
        :ets.insert(@table, {ets_key, %{state | blocked_until: blocked_until}})
    end

    Logger.warning(
      "Circuit breaker opened for key=#{inspect(key)} operation=#{operation} until=#{blocked_until}"
    )

    :ok
  end

  # Propagates the :auth_error ban to all nodes except for the current node.
  # Does NOT run on the caller's node.
  defp maybe_open_globally(key, :auth_error = operation, blocked_until)
       when is_integer(blocked_until) do
    nodes = Node.list()

    nodes
    |> :erpc.multicall(__MODULE__, :open, [key, operation, blocked_until], 10_000)
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

  defp maybe_open_globally(_, _, _), do: :ok

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
