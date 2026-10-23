defmodule Supavisor.Protocol.SessionLeaks do
  @moduledoc """
  Detects statements that leave session state behind in transaction mode.

  In transaction mode consecutive transactions may run on different backend
  connections, so state that outlives a transaction leaks across clients
  instead of applying to the session the client sees. Besides session-level
  `SET` this covers `set_config/3`, `DISCARD`, session-scoped advisory locks,
  `LISTEN`/`UNLISTEN`, `WITH HOLD` cursors, temp tables and `LOAD`.
  Transaction-scoped counterparts (`SET LOCAL`, `SET TRANSACTION`,
  `ON COMMIT DROP`, `SET CONSTRAINTS`) are safe and never flagged.

  The tenant's `txn_mode_leak_action` field picks what happens when
  one is detected:

  * `:ignore` (default) - pass through silently
  * `:log` - pass through and log a warning
  * `:error` - return an error to the client
  """

  require Logger

  alias Supavisor.Errors.SessionLeakError
  alias Supavisor.PgParser

  @type action() :: :ignore | :log | :error

  @doc """
  Checks a parsed query for statements that leave session state behind,
  applying the given action.

  The log message leaves out the query text, which may carry secrets passed as
  literals, such as `set_config('app.token', '...', false)`.
  """
  @spec check(action(), PgParser.parsed()) :: :ok | {:error, SessionLeakError.t()}
  def check(:ignore, _parsed), do: :ok

  def check(action, parsed) do
    case {PgParser.session_leak(parsed), action} do
      {nil, _action} ->
        :ok

      {leak, :log} ->
        Logger.warning("received #{describe(leak)} in transaction mode")
        :ok

      {leak, :error} ->
        {:error, %SessionLeakError{leak: leak}}
    end
  end

  @doc """
  A phrase naming what the statement leaves behind, for log and error messages.
  """
  @spec describe(PgParser.session_leak()) :: String.t()
  def describe(:session_set), do: "session-level SET statement"
  def describe(:set_config), do: "session-level set_config() call"
  def describe(:discard), do: "DISCARD statement"
  def describe(:advisory_lock), do: "session-level advisory lock"
  def describe(:listen), do: "LISTEN statement"
  def describe(:hold_cursor), do: "WITH HOLD cursor"
  def describe(:temp_table), do: "temporary table creation"
  def describe(:load), do: "LOAD statement"
end
