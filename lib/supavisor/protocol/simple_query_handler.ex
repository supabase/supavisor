defmodule Supavisor.Protocol.SimpleQueryHandler do
  @moduledoc """
  Handles PostgreSQL Simple Query (Q) messages.

  This module processes simple query messages and enforces restrictions,
  such as preventing the use of PREPARE statements in simple queries.
  """

  alias Supavisor.PgParser

  @type pkt() :: binary()

  @prepared_statements_stmts MapSet.new([
                               "DeallocateStmt",
                               "PrepareStmt",
                               "ExecuteStmt"
                             ])

  @doc """
  Handles a Simple Query (Q) message.

  Validates the query and returns an error if PREPARE statements are detected,
  otherwise passes the query through unchanged.

  `parsed` is the query tree from `Supavisor.PgParser.parse/1`, or `nil` when
  the query could not be parsed, in which case it passes through.
  """
  @spec handle_simple_query_message(any(), non_neg_integer(), binary(), PgParser.parsed() | nil) ::
          {:ok, any(), pkt()} | {:error, Supavisor.Errors.SimpleQueryNotSupportedError.t()}
  def handle_simple_query_message(state, len, payload, nil),
    do: {:ok, state, <<?Q, len::32, payload::binary>>}

  def handle_simple_query_message(state, len, payload, parsed) do
    types = PgParser.parsed_statement_types(parsed)

    if MapSet.disjoint?(MapSet.new(types), @prepared_statements_stmts) do
      {:ok, state, <<?Q, len::32, payload::binary>>}
    else
      {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}}
    end
  end
end
