defmodule Supavisor.PgParser do
  @moduledoc false

  use Rustler, otp_app: :supavisor, crate: "pgparser"

  # When your NIF is loaded, it will override this function.
  @doc """
  Returns a list of all statements in the given sql string.

  ## Examples

      iex> Supavisor.PgParser.statement_types("select 1; insert into table1 values ('a', 'b')")
      {:ok, ["SelectStmt", "InsertStmt"]}

      iex> Supavisor.PgParser.statement_types("not a valid sql")
      {:error, "Error parsing query"}
  """
  @spec statement_types(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def statement_types(_query), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Returns whether the given sql string contains a session-level SET statement.

  Transaction-scoped variants (`SET LOCAL`, `SET TRANSACTION`) don't count.

  ## Examples

      iex> Supavisor.PgParser.has_session_set("set statement_timeout = '1s'")
      {:ok, true}

      iex> Supavisor.PgParser.has_session_set("set local statement_timeout = '1s'")
      {:ok, false}

      iex> Supavisor.PgParser.has_session_set("select 1")
      {:ok, false}

      iex> Supavisor.PgParser.has_session_set("not a valid sql")
      {:error, "Error parsing query"}
  """
  @spec has_session_set(String.t()) :: {:ok, boolean()} | {:error, String.t()}
  def has_session_set(_query), do: :erlang.nif_error(:nif_not_loaded)

  @spec statements(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def statements(query) when is_binary(query), do: statement_types(query)
  def statements(_), do: {:error, "Query must be a string"}
end
