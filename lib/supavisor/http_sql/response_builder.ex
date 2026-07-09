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

  ## On encoding

  Because the wire path issues `Bind` with `Result-Format-Code = 0` for every
  column (see `Supavisor.HttpSql.Wire.bind/3`), the backend has already
  serialized every cell into PostgreSQL text format before it reaches
  `WireDecoder`. That's exactly what the Neon driver consumes — `pg-types`
  parses the textual representation on the client side using the column's
  `dataTypeID` (OID).

  So cell values pass through here unchanged. No per-OID encoder is needed,
  and the previous `ValueEncoder` (which assumed Postgrex-decoded
  Elixir-native inputs) is gone.
  """

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

    %{
      "command" => command(result.command),
      "rowCount" => result.num_rows || 0,
      "fields" => Enum.with_index(cols) |> Enum.map(&field_meta_from_column/1),
      "rows" => encode_rows(rows, names, array_mode)
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

  # array_mode=true: each row is a positional list of PG text values (or nil).
  # No encoding — backend already returned text format.
  defp encode_rows(rows, _names, true), do: rows

  # array_mode=false: zip each row with its column names into a map.
  defp encode_rows(rows, names, false) do
    Enum.map(rows, fn row -> names |> Enum.zip(row) |> Map.new() end)
  end
end
