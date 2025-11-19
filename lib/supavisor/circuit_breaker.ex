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
  Records a failure for a given tenant and operation.
  """
  @spec record_failure(String.t(), atom()) :: :ok
  def record_failure(tenant, operation) when is_binary(tenant) and is_atom(operation) do
    now = System.system_time(:second)
    key = {tenant, operation}

    case :ets.lookup(@table, key) do
      [] ->
        :ets.insert(@table, {key, %{failures: [now], blocked_until: nil}})

      [{^key, state}] ->
        threshold = Map.fetch!(@thresholds, operation)
        window_start = now - threshold.window_seconds

        recent_failures = Enum.filter([now | state.failures], &(&1 >= window_start))

        blocked_until =
          if length(recent_failures) >= threshold.max_failures do
            block_until = now + threshold.block_seconds

            Logger.warning(
              "Circuit breaker opened for tenant=#{tenant} operation=#{operation} until=#{block_until}"
            )

            block_until
          else
            state.blocked_until
          end

        :ets.insert(@table, {key, %{failures: recent_failures, blocked_until: blocked_until}})
    end

    :ok
  end

  @doc """
  Checks if a circuit breaker is open for a given tenant and operation.
  Returns :ok if operation is allowed, {:error, :circuit_open, blocked_until} otherwise.
  """
  @spec check(String.t(), atom()) :: :ok | {:error, :circuit_open, integer()}
  def check(tenant, operation) when is_binary(tenant) and is_atom(operation) do
    now = System.system_time(:second)
    key = {tenant, operation}

    case :ets.lookup(@table, key) do
      [] ->
        :ok

      [{^key, %{blocked_until: nil}}] ->
        :ok

      [{^key, %{blocked_until: blocked_until}}] when blocked_until > now ->
        {:error, :circuit_open, blocked_until}

      [{^key, state}] ->
        :ets.insert(@table, {key, %{state | blocked_until: nil}})
        :ok
    end
  end

  @doc """
  Clears circuit breaker state for a tenant and operation.
  """
  @spec clear(String.t(), atom()) :: :ok
  def clear(tenant, operation) when is_binary(tenant) and is_atom(operation) do
    :ets.delete(@table, {tenant, operation})
    :ok
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
