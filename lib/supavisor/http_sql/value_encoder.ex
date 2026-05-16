defmodule Supavisor.HttpSql.ValueEncoder do
  @moduledoc """
  Encodes Postgrex-decoded Elixir terms back into Postgres **text format**
  strings, indexed by column OID. The Neon `/sql` wire format ships every
  cell as either `null` or a JSON string in Postgres text representation;
  clients (`@neondatabase/serverless`, `drizzle-orm/neon-http`, etc.) parse
  the string locally via `pg-types` using the OID we report in `fields[]`.

  Unknown OIDs fall through to a best-effort `to_string/1` (logged once via
  `:persistent_term`). nil round-trips to nil so the row builder can emit
  JSON `null`.
  """

  require Logger

  # Scalar element OIDs reachable through array OIDs in `@array_element/0`.
  @bool 16
  @bytea 17
  @char 18
  @name 19
  @int8 20
  @int2 21
  @int4 23
  @text 25
  @json 114
  @float4 700
  @float8 701
  @varchar 1043
  @date 1082
  @time 1083
  @timestamp 1114
  @timestamptz 1184
  @interval 1186
  @numeric 1700
  @uuid 2950
  @jsonb 3802

  # Array OID → element OID
  @array_element %{
    1000 => @bool,
    1001 => @bytea,
    1002 => @char,
    1003 => @name,
    1005 => @int2,
    1007 => @int4,
    1009 => @text,
    1015 => @varchar,
    1016 => @int8,
    1021 => @float4,
    1022 => @float8,
    1115 => @timestamp,
    1182 => @date,
    1183 => @time,
    1185 => @timestamptz,
    1187 => @interval,
    1231 => @numeric,
    2951 => @uuid,
    199 => @json,
    3807 => @jsonb
  }

  @doc """
  Encode a single Elixir term to a Postgres text-format string, or `nil`
  for SQL `NULL`. Dispatches on the column OID.
  """
  @spec encode(term :: any, oid :: non_neg_integer) :: String.t() | nil
  def encode(nil, _oid), do: nil

  # --- Booleans
  def encode(true, @bool), do: "t"
  def encode(false, @bool), do: "f"

  # --- Integers (int2/int4/int8)
  def encode(v, oid) when oid in [@int2, @int4, @int8] and is_integer(v),
    do: Integer.to_string(v)

  # --- Floats (float4/float8)
  def encode(:nan, oid) when oid in [@float4, @float8], do: "NaN"
  def encode(:infinity, oid) when oid in [@float4, @float8], do: "Infinity"
  def encode(:negative_infinity, oid) when oid in [@float4, @float8], do: "-Infinity"

  def encode(v, oid) when oid in [@float4, @float8] and is_float(v),
    do: Float.to_string(v)

  def encode(v, oid) when oid in [@float4, @float8] and is_integer(v),
    do: Integer.to_string(v) <> ".0"

  # --- Text-like (text/varchar/char/name/bpchar)
  def encode(v, oid) when oid in [@text, @varchar, @char, @name] and is_binary(v), do: v
  def encode(v, 1042) when is_binary(v), do: v

  # --- Bytea: PG hex format `\xDEADBEEF`
  def encode(v, @bytea) when is_binary(v),
    do: "\\x" <> Base.encode16(v, case: :lower)

  # --- Numeric
  def encode(%Decimal{} = v, @numeric), do: Decimal.to_string(v, :normal)
  def encode(v, @numeric) when is_integer(v), do: Integer.to_string(v)
  def encode(v, @numeric) when is_float(v), do: Float.to_string(v)

  # --- Date/Time/Timestamp
  def encode(%Date{} = v, @date), do: Date.to_iso8601(v)
  def encode(%Time{} = v, @time), do: Time.to_iso8601(v)

  def encode(%NaiveDateTime{} = v, @timestamp),
    do: NaiveDateTime.to_iso8601(v) |> String.replace("T", " ")

  def encode(%DateTime{} = v, @timestamptz) do
    # libpq emits e.g. "2026-05-15 14:30:00+00" (space, no T, abbreviated zone)
    v
    |> DateTime.shift_zone!("Etc/UTC")
    |> DateTime.to_iso8601()
    |> String.replace("T", " ")
    |> String.replace(~r/\.\d+/, fn frac -> frac end)
    |> String.replace(~r/Z$/, "+00")
  end

  # --- Interval: Postgrex.Interval has `to_string/1` but no String.Chars
  # protocol impl — `to_string(v)` (the kernel function) would raise
  # `Protocol.UndefinedError`. Call the module function directly.
  def encode(%Postgrex.Interval{} = v, @interval), do: Postgrex.Interval.to_string(v)

  def encode(%{months: _, days: _, secs: _, microsecs: _} = v, @interval),
    do: Postgrex.Interval.to_string(struct(Postgrex.Interval, v))

  # --- UUID: Postgrex hands back the 16-byte binary; format as canonical hex
  def encode(<<a::32, b::16, c::16, d::16, e::48>>, @uuid) do
    :io_lib.format("~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", [a, b, c, d, e])
    |> IO.iodata_to_binary()
  end

  def encode(v, @uuid) when is_binary(v) and byte_size(v) == 36, do: v

  # --- JSON / JSONB: Postgrex decodes into Elixir terms; we re-serialize
  def encode(v, oid) when oid in [@json, @jsonb], do: Jason.encode!(v)

  # --- Arrays: encode each element with the element OID, join in PG syntax
  def encode(v, array_oid) when is_list(v) and is_map_key(@array_element, array_oid) do
    element_oid = Map.fetch!(@array_element, array_oid)
    "{" <> Enum.map_join(v, ",", &encode_array_element(&1, element_oid)) <> "}"
  end

  # --- Fallback: best-effort to_string, warn-once per OID
  def encode(v, oid) do
    warn_unknown_oid(oid, v)

    cond do
      is_binary(v) -> v
      is_atom(v) -> Atom.to_string(v)
      is_number(v) -> to_string(v)
      true -> inspect(v)
    end
  end

  @doc """
  Encode a single row (`[term]`) to a list of text/nil cells, given the list
  of column OIDs (`[non_neg_integer]`) returned by `Postgrex.Query.result_oids`.
  """
  @spec encode_row([term], [non_neg_integer]) :: [String.t() | nil]
  def encode_row(row, oids) when length(row) == length(oids) do
    row
    |> Enum.zip(oids)
    |> Enum.map(fn {v, oid} -> encode(v, oid) end)
  end

  # ---------------------------------------------------------------------------

  defp encode_array_element(nil, _oid), do: "NULL"

  defp encode_array_element(v, oid) when is_list(v) do
    # Nested arrays: recurse using the parent array OID's element type
    "{" <> Enum.map_join(v, ",", &encode_array_element(&1, oid)) <> "}"
  end

  defp encode_array_element(v, oid) do
    text = encode(v, oid)
    if needs_array_quoting?(text), do: "\"" <> escape_array_string(text) <> "\"", else: text
  end

  defp needs_array_quoting?(""), do: true
  defp needs_array_quoting?("NULL"), do: true

  defp needs_array_quoting?(s) when is_binary(s) do
    String.contains?(s, [",", "{", "}", "\"", "\\"]) or
      String.match?(s, ~r/\s/)
  end

  defp escape_array_string(s) do
    s
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end

  defp warn_unknown_oid(oid, sample) do
    key = {__MODULE__, :unknown_oid, oid}

    case :persistent_term.get(key, :unset) do
      :unset ->
        :persistent_term.put(key, :warned)

        Logger.warning(
          "ValueEncoder: no text encoder for OID #{oid}, falling back to to_string/inspect (sample: #{inspect(sample, limit: 50)})"
        )

      _ ->
        :ok
    end
  end
end
