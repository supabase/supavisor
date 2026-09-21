defmodule Supavisor.PgParser do
  @moduledoc """
  Parses SQL with libpg_query.

  Parsing dominates the cost of every check, so a query is parsed once with
  `parse/1` and the resulting tree is handed to as many checks as the caller
  needs.
  """

  use Rustler, otp_app: :supavisor, crate: "pgparser"

  @typedoc "An opaque parsed query tree, produced by `parse/1`"
  @opaque parsed() :: reference()

  @doc """
  Parses a query into a tree that the functions below can inspect.

  ## Examples

      iex> {:ok, parsed} = Supavisor.PgParser.parse("select 1")
      iex> Supavisor.PgParser.statement_types(parsed)
      ["SelectStmt"]

      iex> Supavisor.PgParser.parse("not a valid sql")
      {:error, "Error parsing query"}
  """
  @spec parse(String.t()) :: {:ok, parsed()} | {:error, String.t()}
  def parse(_query), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Returns a list of all statements in a parsed query.

  ## Examples

      iex> {:ok, parsed} = Supavisor.PgParser.parse("select 1; insert into table1 values ('a', 'b')")
      iex> Supavisor.PgParser.statement_types(parsed)
      ["SelectStmt", "InsertStmt"]
  """
  @spec statement_types(parsed()) :: [String.t()]
  def statement_types(_parsed), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Returns whether a parsed query contains a session-level SET statement.

  Transaction-scoped variants (`SET LOCAL`, `SET TRANSACTION`) don't count.

  ## Examples

      iex> {:ok, parsed} = Supavisor.PgParser.parse("set statement_timeout = '1s'")
      iex> Supavisor.PgParser.has_session_set(parsed)
      true

      iex> {:ok, parsed} = Supavisor.PgParser.parse("set local statement_timeout = '1s'")
      iex> Supavisor.PgParser.has_session_set(parsed)
      false

      iex> {:ok, parsed} = Supavisor.PgParser.parse("select 1")
      iex> Supavisor.PgParser.has_session_set(parsed)
      false
  """
  @spec has_session_set(parsed()) :: boolean()
  def has_session_set(_parsed), do: :erlang.nif_error(:nif_not_loaded)
end
