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

  @typedoc """
  The kind of session state a query leaves behind, or `nil` when it leaves none.
  """
  @type session_leak() ::
          nil
          | :session_set
          | :set_config
          | :discard
          | :advisory_lock
          | :listen
          | :hold_cursor
          | :temp_table
          | :set_constraints
          | :load

  @doc """
  Returns the kind of state left on the backend by the first statement in a
  parsed query that outlives the transaction, or `nil` when none does.

  Besides session-level `SET`, this covers `set_config/3` with `is_local` false,
  `DISCARD`, session-scoped advisory locks, `LISTEN`/`UNLISTEN`, `WITH HOLD`
  cursors, temp tables, `SET CONSTRAINTS` and `LOAD`.

  Transaction-scoped counterparts (`SET LOCAL`, `SET TRANSACTION`,
  `set_config(_, _, true)`, `pg_advisory_xact_lock/1`, `ON COMMIT DROP`) don't
  count.

  When several statements leak, the first one in statement order is reported.

  ## Examples

      iex> {:ok, parsed} = Supavisor.PgParser.parse("set statement_timeout = '1s'")
      iex> Supavisor.PgParser.session_leak(parsed)
      :session_set

      iex> {:ok, parsed} = Supavisor.PgParser.parse("set local statement_timeout = '1s'")
      iex> Supavisor.PgParser.session_leak(parsed)
      nil

      iex> {:ok, parsed} = Supavisor.PgParser.parse("select set_config('search_path', 'public', false)")
      iex> Supavisor.PgParser.session_leak(parsed)
      :set_config

      iex> {:ok, parsed} = Supavisor.PgParser.parse("discard all")
      iex> Supavisor.PgParser.session_leak(parsed)
      :discard

      iex> {:ok, parsed} = Supavisor.PgParser.parse("select 1")
      iex> Supavisor.PgParser.session_leak(parsed)
      nil
  """
  @spec session_leak(parsed()) :: session_leak()
  def session_leak(_parsed), do: :erlang.nif_error(:nif_not_loaded)
end
