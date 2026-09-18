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
  Checks a Simple Query (Q) or Parse (P) message payload for session-level SET
  statements, applying the given action. Other message types pass through.
  """
  @spec check(action() | nil, byte(), binary()) ::
          :ok | {:error, SetStatementNotAllowedError.t()}
  def check(action, _tag, _payload) when action in [nil, :ignore], do: :ok

  def check(action, ?Q, payload) do
    check_query(action, String.trim_trailing(payload, <<0>>))
  end

  def check(action, ?P, payload) do
    with [_name, rest] <- :binary.split(payload, <<0>>),
         [query, _] <- :binary.split(rest, <<0>>) do
      check_query(action, query)
    else
      _ -> :ok
    end
  end

  def check(_action, _tag, _payload), do: :ok

  @doc """
  Same as `check/3` for a Simple Query whose tree has already been parsed by
  `Supavisor.PgParser.parse/1`, avoiding a second parse of the same query.
  """
  @spec check_parsed(action() | nil, PgParser.parsed() | nil, binary()) ::
          :ok | {:error, SetStatementNotAllowedError.t()}
  def check_parsed(action, _parsed, _query) when action in [nil, :ignore], do: :ok
  def check_parsed(_action, nil, _query), do: :ok

  def check_parsed(action, parsed, query) do
    if PgParser.parsed_has_session_set(parsed) do
      handle_detected(action, query)
    else
      :ok
    end
  end

  defp check_query(action, query) do
    case PgParser.has_session_set(query) do
      {:ok, true} -> handle_detected(action, query)
      _ -> :ok
    end
  end

  defp handle_detected(:log, query) do
    Logger.warning("received session-level SET statement in transaction mode: #{query}")
    :ok
  end

  defp handle_detected(:error, _query) do
    {:error, %SetStatementNotAllowedError{}}
  end
end
