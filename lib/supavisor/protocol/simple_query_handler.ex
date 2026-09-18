defmodule Supavisor.Protocol.SimpleQueryHandler do
  @moduledoc """
  Restrictions on PostgreSQL Simple Query (Q) messages.

  Transaction mode only supports prepared statements through the Extended
  Query Protocol, so `PREPARE`, `EXECUTE` and `DEALLOCATE` are rejected when
  they arrive as a simple query.
  """

  alias Supavisor.Errors.SimpleQueryNotSupportedError
  alias Supavisor.PgParser

  @prepared_statements_stmts MapSet.new([
                               "DeallocateStmt",
                               "PrepareStmt",
                               "ExecuteStmt"
                             ])

  @doc """
  Rejects a parsed simple query that uses prepared statement commands.

  Does nothing unless `enabled?` is true, since the check is opt-in per tenant.
  `parsed` is the tree from `Supavisor.PgParser.parse/1`, or `nil` when the
  query could not be parsed, in which case it is allowed through.
  """
  @spec check(boolean(), PgParser.parsed() | nil) ::
          :ok | {:error, SimpleQueryNotSupportedError.t()}
  def check(false, _parsed), do: :ok
  def check(_enabled?, nil), do: :ok

  def check(_enabled?, parsed) do
    types = MapSet.new(PgParser.parsed_statement_types(parsed))

    if MapSet.disjoint?(types, @prepared_statements_stmts) do
      :ok
    else
      {:error, %SimpleQueryNotSupportedError{}}
    end
  end
end
