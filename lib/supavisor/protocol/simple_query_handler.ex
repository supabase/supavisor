defmodule Supavisor.Protocol.SimpleQueryHandler do
  @moduledoc """
  Restrictions on PostgreSQL Simple Query (Q) messages in transaction mode.

  Two checks run on the query, both opt-in per tenant:

  * session-level SET statements, delegated to `Supavisor.Protocol.SetStatements`
  * `PREPARE`, `EXECUTE` and `DEALLOCATE`, which transaction mode only supports
    through the Extended Query Protocol

  Both need the query parsed and parsing dominates their cost, so the query is
  parsed once here and each check walks the resulting tree. An unparseable
  query is passed through for the backend to reject.
  """

  require Logger

  alias Supavisor.Errors.SimpleQueryNotSupportedError
  alias Supavisor.PgParser
  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.Storage
  alias Supavisor.Protocol.SetStatements

  @prepared_statements_stmts MapSet.new([
                               "DeallocateStmt",
                               "PrepareStmt",
                               "ExecuteStmt"
                             ])

  @doc """
  Handles a Simple Query (Q) message. The query is forwarded unchanged unless
  one of the enabled checks rejects it.
  """
  @spec handle_message(map(), non_neg_integer(), binary()) ::
          {:ok, Storage.t(), PreparedStatements.pkt()} | {:error, Exception.t()}
  def handle_message(state, len, payload) do
    with :ok <-
           check_message(state.set_statements_action, state.check_simple_query_prepare?, payload) do
      {:ok, state.prepared_statements, <<?Q, len::32, payload::binary>>}
    end
  end

  defp check_message(set_action, prepare_check?, payload) do
    set_check? = set_action != :ignore

    with true <- set_check? or prepare_check?,
         # Some clients send null terminators
         query = String.trim_trailing(payload, <<0>>),
         {:ok, parsed} <- parse(query),
         :ok <- if(set_check?, do: SetStatements.check(set_action, parsed, query), else: :ok) do
      if prepare_check?, do: check_prepared_statements(parsed), else: :ok
    else
      {:error, _} = error -> error
      _ -> :ok
    end
  end

  defp check_prepared_statements(parsed) do
    types = MapSet.new(PgParser.statement_types(parsed))

    if MapSet.disjoint?(types, @prepared_statements_stmts) do
      :ok
    else
      {:error, %SimpleQueryNotSupportedError{}}
    end
  end

  defp parse(query) do
    case PgParser.parse(query) do
      {:ok, parsed} ->
        {:ok, parsed}

      {:error, error} ->
        Logger.debug("Failed to parse simple query: #{inspect(error)}, query: #{inspect(query)}")
        :unparseable
    end
  end
end
