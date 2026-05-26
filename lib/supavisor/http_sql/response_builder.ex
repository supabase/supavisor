defmodule Supavisor.HttpSql.ResponseBuilder do
  @moduledoc """
  Builds the Neon `/sql` JSON response body from the structured result
  produced by `Supavisor.HttpSql.WireDecoder`.

  Single shape:

      %{
        "command"  => "SELECT",
        "rowCount" => N,
        "fields"   => [ %{name, dataTypeID, dataTypeSize, dataTypeModifier, format} ],
        "rows"     => [ [text_or_null, ...] ]    # array_mode=true
                   or [ %{column_name => text_or_null} ]  # array_mode=false
      }

  Batch shape (one entry per query, server-side BEGIN..COMMIT):

      %{ "results" => [ <single>, <single>, ... ] }
  """

  alias Supavisor.HttpSql.ValueEncoder

  @type column :: %{name: String.t(), oid: pos_integer()}

  @type query_result :: %{
          required(:columns) => [column()] | nil,
          required(:rows) => [[binary() | nil]],
          required(:command) => String.t() | nil,
          required(:num_rows) => non_neg_integer()
        }

  @type opts :: %{
          optional(:array_mode) => boolean
        }

  @doc """
  Build a single-query response body.
  """
  @spec build_single(query_result, opts) :: map
  def build_single(result, opts \\ %{})

  def build_single(%{rows: rows} = result, opts) when is_list(rows) do
    array_mode = Map.get(opts, :array_mode, false)
    cols = result.columns || []
    names = Enum.map(cols, & &1.name)
    oids = Enum.map(cols, & &1.oid)

    %{
      "command" => command(result.command),
      "rowCount" => result.num_rows || 0,
      "fields" => Enum.with_index(cols) |> Enum.map(&field_meta_from_column/1),
      "rows" => encode_rows(rows, names, oids, array_mode)
    }
  end

  @doc """
  Build a batch response body wrapping a list of per-query results.
  """
  @spec build_batch([query_result], opts) :: map
  def build_batch(results, opts \\ %{}) when is_list(results) do
    %{"results" => Enum.map(results, &build_single(&1, opts))}
  end

  # ---------------------------------------------------------------------------

  defp command(nil), do: "UNKNOWN"
  defp command(atom) when is_atom(atom), do: atom |> Atom.to_string() |> String.upcase()
  defp command(binary) when is_binary(binary), do: String.upcase(binary)

  defp field_meta_from_column({%{name: name, oid: oid}, _idx}) do
    %{
      "name" => to_string(name),
      "dataTypeID" => oid || 0,
      "dataTypeSize" => -1,
      "dataTypeModifier" => -1,
      "format" => "text"
    }
  end

  defp encode_rows(rows, _columns, oids, true = _array_mode) do
    Enum.map(rows, fn row -> ValueEncoder.encode_row(row, pad_oids(oids, row)) end)
  end

  defp encode_rows(rows, columns, oids, false = _array_mode) do
    Enum.map(rows, fn row ->
      cells = ValueEncoder.encode_row(row, pad_oids(oids, row))

      columns
      |> Enum.zip(cells)
      |> Enum.into(%{})
    end)
  end

  # Defensive: if Postgrex didn't give us result_oids (rare with prepare_execute,
  # possible with raw simple-query), fall back to 0 (text-cat fallback in encoder).
  defp pad_oids(oids, row) do
    case length(oids) == length(row) do
      true -> oids
      false -> List.duplicate(0, length(row))
    end
  end
end
