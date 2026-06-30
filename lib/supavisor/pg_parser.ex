defmodule Supavisor.PgParser do
  @moduledoc false

  use Rustler, otp_app: :supavisor, crate: "pgparser"

  @doc """
  Returns a list of all statements in the given sql string.

  ## Examples

      iex> Supavisor.PgParser.statements("select 1; insert into table1 values ('a', 'b')")
      {:ok, ["SelectStmt", "InsertStmt"]}

      iex> Supavisor.PgParser.statements("not a valid sql")
      {:error, "Error parsing query"}
  """
  @spec statements(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def statements(query) when is_binary(query), do: statement_types(query)
  def statements(_), do: {:error, "Query must be a string"}

  @doc """
  Returns the full parse tree of the given SQL string.
  """
  @spec parse(String.t()) :: {:ok, map()} | {:error, String.t()}
  def parse(query) when is_binary(query) do
    with {:ok, json} <- parse_to_json(query),
         {:ok, tree} <- Jason.decode(json) do
      {:ok, tree}
    else
      {:error, %Jason.DecodeError{} = e} -> {:error, Exception.message(e)}
      {:error, _} = err -> err
    end
  end

  def parse(_), do: {:error, "Query must be a string"}

  # When your NIFs are loaded, it will override these functions:

  @spec statement_types(String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  defp statement_types(_query), do: :erlang.nif_error(:nif_not_loaded)

  @spec parse_to_json(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defp parse_to_json(_query), do: :erlang.nif_error(:nif_not_loaded)
end
