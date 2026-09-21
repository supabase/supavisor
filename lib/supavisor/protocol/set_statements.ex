defmodule Supavisor.Protocol.SetStatements do
  @moduledoc """
  Detects session-level SET statements sent by clients in transaction mode.

  In transaction mode consecutive transactions may run on different backend
  connections, so session-level SET statements leak state across clients
  instead of applying to the session the client sees. Transaction-scoped
  variants (`SET LOCAL`, `SET TRANSACTION`) are safe and never flagged.

  The tenant's `txn_mode_set_action` field picks what happens when
  one is detected:

  * `:ignore` (default) - pass through silently
  * `:log` - pass through and log a warning
  * `:error` - return an error to the client
  """

  require Logger

  alias Supavisor.Errors.SetStatementNotAllowedError
  alias Supavisor.PgParser

  @type action() :: :ignore | :log | :error

  @doc """
  Checks a parsed query for session-level SET statements, applying the given
  action. `query` is only used for logging.
  """
  @spec check(action(), PgParser.parsed(), binary()) ::
          :ok | {:error, SetStatementNotAllowedError.t()}
  def check(:ignore, _parsed, _query), do: :ok

  def check(action, parsed, query) do
    if PgParser.has_session_set(parsed) do
      case action do
        :log ->
          Logger.warning("received session-level SET statement in transaction mode: #{query}")
          :ok

        :error ->
          {:error, %SetStatementNotAllowedError{}}
      end
    else
      :ok
    end
  end
end
