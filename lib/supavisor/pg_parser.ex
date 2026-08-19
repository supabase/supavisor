defmodule Supavisor.PgParser do
  @moduledoc false

  # Pure C NIF (directly linked against libpg_query); see native/pgparser/Makefile.
  # The return shape of statement_types/1 is the stable upward contract; never change it.
  @on_load :load_nif

  def load_nif do
    # Runtime load path inside priv; the artifact is built from native/pgparser/.
    nif_path = :filename.join(:code.priv_dir(:supavisor), ~c"native/pgparser")
    cache_size = Application.get_env(:supavisor, :parser_cache_size, 1024)
    :erlang.load_nif(nif_path, cache_size)
  end

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
  Returns aggregated counters of the per-scheduler parse cache.

  Counters are cumulative since VM start and approximate (read without
  locking on the hot path). Keys: `:hits`, `:misses`, `:bypasses`,
  `:bypass_allowlist`, `:bypass_multi_statement`, `:bypass_scan_error`,
  `:bypass_unsafe_literal`, `:inserts`, `:evictions`, `:entries`, `:parses`,
  `:parse_errors`, `:schedulers`, `:max_entries`.
  """
  @spec cache_stats() :: %{optional(atom) => non_neg_integer}
  def cache_stats, do: :erlang.nif_error(:nif_not_loaded)

  @spec statements(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def statements(query) when is_binary(query), do: statement_types(query)
  def statements(_), do: {:error, "Query must be a string"}
end
