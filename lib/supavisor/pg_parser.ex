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

  Queries with long runs of operator characters are rejected with
  `:too_complex` before parsing. The Postgres scanner takes time quadratic in
  the length of such a run.

  ## Examples

      iex> {:ok, parsed} = Supavisor.PgParser.parse("select 1")
      iex> Supavisor.PgParser.statement_types(parsed)
      ["SelectStmt"]

      iex> Supavisor.PgParser.parse("not a valid sql")
      {:error, :syntax_error}

      iex> Supavisor.PgParser.parse(<<"select 'caf", 0xE9, "'">>)
      {:error, :invalid_utf8}

      iex> Supavisor.PgParser.parse("select " <> String.duplicate("+", 300) <> "1")
      {:error, :too_complex}
  """
  @spec parse(binary()) ::
          {:ok, parsed()} | {:error, :invalid_utf8 | :too_complex | :syntax_error}
  def parse(_query), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Same as `parse/1`, on a dirty CPU scheduler, for queries too large to parse
  on a normal one.

  ## Examples

      iex> {:ok, parsed} = Supavisor.PgParser.parse_dirty("select 1")
      iex> Supavisor.PgParser.statement_types(parsed)
      ["SelectStmt"]
  """
  @spec parse_dirty(binary()) ::
          {:ok, parsed()} | {:error, :invalid_utf8 | :too_complex | :syntax_error}
  def parse_dirty(_query), do: :erlang.nif_error(:nif_not_loaded)

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
          | :load

  @doc """
  Returns the kind of state left on the backend by the first statement in a
  parsed query that outlives the transaction, or `nil` when none does.

  Besides session-level `SET`, this covers `set_config/3` with a literal
  `is_local` of false,
  `DISCARD`, session-scoped advisory locks, `LISTEN`/`UNLISTEN`, `WITH HOLD`
  cursors, temp tables and `LOAD`.

  Transaction-scoped counterparts (`SET LOCAL`, `SET TRANSACTION`,
  `set_config(_, _, true)`, `pg_advisory_xact_lock/1`, `ON COMMIT DROP`,
  `SET CONSTRAINTS`) don't count.

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
