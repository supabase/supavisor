defmodule Supavisor.HttpSql.Transaction do
  @moduledoc """
  Builds a `SET TRANSACTION ...` SQL statement from the Neon-Batch-* HTTP
  headers, validating each value against a strict allow-list so unknown or
  injected values cannot reach Postgres.

  Used by `Supavisor.HttpSql.execute_batch/3` to scope the BEGIN..COMMIT
  transaction around a `queries: [...]` batch.

  Supported headers:

    * `Neon-Batch-Isolation-Level`:
      `"ReadUncommitted" | "ReadCommitted" | "RepeatableRead" | "Serializable"`
    * `Neon-Batch-Read-Only`: `"true" | "false"` → `READ ONLY` / `READ WRITE`
    * `Neon-Batch-Deferrable`: `"true" | "false"` → `DEFERRABLE` / `NOT DEFERRABLE`

  Returns `{:ok, nil}` when no headers are present (caller skips the SET
  statement), `{:ok, sql}` when at least one is present, or `{:error, ...}`
  with an offending field for validation failures.
  """

  @isolation_levels %{
    "readuncommitted" => "READ UNCOMMITTED",
    "readcommitted" => "READ COMMITTED",
    "repeatableread" => "REPEATABLE READ",
    "serializable" => "SERIALIZABLE"
  }

  @type batch_opts :: %{
          optional(:isolation) => String.t() | nil,
          optional(:read_only) => String.t() | nil,
          optional(:deferrable) => String.t() | nil
        }

  @type error ::
          {:invalid_isolation, String.t()}
          | {:invalid_read_only, String.t()}
          | {:invalid_deferrable, String.t()}

  @doc """
  Build the `SET TRANSACTION ...` SQL fragment from a map of normalized
  header values. Missing keys (or `nil` values) are skipped.
  """
  @spec build(batch_opts) :: {:ok, String.t() | nil} | {:error, error}
  def build(opts) when is_map(opts) do
    with {:ok, iso} <- parse_isolation(Map.get(opts, :isolation)),
         {:ok, ro} <- parse_read_only(Map.get(opts, :read_only)),
         {:ok, def_} <- parse_deferrable(Map.get(opts, :deferrable)) do
      parts = Enum.reject([iso, ro, def_], &is_nil/1)

      case parts do
        [] -> {:ok, nil}
        _ -> {:ok, "SET TRANSACTION " <> Enum.join(parts, " ")}
      end
    end
  end

  @doc """
  Pull the three Neon-Batch-* headers out of a `Plug.Conn`'s request headers
  list and normalize them to lowercase string values (or `nil`).
  """
  @spec from_headers([{String.t(), String.t()}]) :: batch_opts
  def from_headers(req_headers) when is_list(req_headers) do
    %{
      isolation: header(req_headers, "neon-batch-isolation-level"),
      read_only: header(req_headers, "neon-batch-read-only"),
      deferrable: header(req_headers, "neon-batch-deferrable")
    }
  end

  # ---------------------------------------------------------------------------

  defp parse_isolation(nil), do: {:ok, nil}

  defp parse_isolation(level) when is_binary(level) do
    key = level |> String.downcase() |> String.replace([" ", "-", "_"], "")

    case Map.fetch(@isolation_levels, key) do
      {:ok, sql} -> {:ok, "ISOLATION LEVEL " <> sql}
      :error -> {:error, {:invalid_isolation, level}}
    end
  end

  defp parse_read_only(nil), do: {:ok, nil}
  defp parse_read_only("true"), do: {:ok, "READ ONLY"}
  defp parse_read_only("false"), do: {:ok, "READ WRITE"}
  defp parse_read_only(other), do: {:error, {:invalid_read_only, other}}

  defp parse_deferrable(nil), do: {:ok, nil}
  defp parse_deferrable("true"), do: {:ok, "DEFERRABLE"}
  defp parse_deferrable("false"), do: {:ok, "NOT DEFERRABLE"}
  defp parse_deferrable(other), do: {:error, {:invalid_deferrable, other}}

  defp header(headers, name) do
    case List.keyfind(headers, name, 0) do
      {_, v} when is_binary(v) and v != "" -> v
      _ -> nil
    end
  end
end
