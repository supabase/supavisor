defmodule Supavisor.Protocol.SimpleQueryHandler do
  @moduledoc """
  Handles PostgreSQL Simple Query (Q) messages.

  Two checks run on the query, both opt-in per tenant:

  * statements leaving session state behind, delegated to
    `Supavisor.Protocol.SessionLeaks`
  * `PREPARE`, `EXECUTE` and `DEALLOCATE`, which transaction mode only supports
    through the Extended Query Protocol

  Both need the query parsed and parsing dominates their cost, so the query is
  parsed once here and each check walks the resulting tree. An unparseable
  query is passed through for the backend to reject.
  """

  alias Supavisor.Errors.SimpleQueryNotSupportedError
  alias Supavisor.PgParser
  alias Supavisor.Protocol.MessageHandlerHelpers
  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.Storage
  alias Supavisor.Protocol.SessionLeaks

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
           check_message(state.leak_action, state.check_simple_query_prepare?, payload) do
      {:ok, state.prepared_statements, <<?Q, len::32, payload::binary>>}
    end
  end

  defp check_message(leak_action, prepare_check?, payload) do
    leak_check? = leak_action != :ignore

    with true <- leak_check? or prepare_check?,
         # Some clients send null terminators
         query = String.trim_trailing(payload, <<0>>),
         {:ok, parsed} <- MessageHandlerHelpers.parse_query(query),
         :ok <- if(leak_check?, do: SessionLeaks.check(leak_action, parsed, query), else: :ok) do
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
end
