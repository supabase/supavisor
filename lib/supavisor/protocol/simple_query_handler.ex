defmodule Supavisor.Protocol.SimpleQueryHandler do
  @moduledoc """
  Handles PostgreSQL Simple Query (Q) messages.

  This module processes simple query messages and enforces restrictions,
  such as preventing the use of PREPARE statements in simple queries.

  Simple queries bypass the extended query protocol and are executed
  directly, but certain operations like PREPARE are not allowed to
  maintain consistency with the prepared statement pooling system.
  """

  @type pkt() :: binary()

  @doc """
  Handles a Simple Query (Q) message.

  Validates the query and returns an error if PREPARE statements are detected,
  otherwise passes the query through unchanged.
  """
  @spec handle_simple_query_message(any(), non_neg_integer(), binary()) ::
          {:ok, any(), pkt()} | {:error, atom()}
  def handle_simple_query_message(state, len, payload) do
    case payload do
      "PREPARE" <> _ ->
        {:error, :prepared_statement_on_simple_query}

      _ ->
        {:ok, state, <<?Q, len::32, payload::binary>>}
    end
  end
end
