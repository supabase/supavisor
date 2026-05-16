defmodule Supavisor.HttpSql.ParamCoercer do
  @moduledoc """
  Convert Neon-driver-style parameter values (everything arrives as a
  JSON string regardless of original type) into the Elixir native types
  Postgrex's binary-bind encoders expect.

  The Neon JS driver serializes every parameter as a string on the wire:
  `42` becomes `"42"`, `true` becomes `"true"`, etc. — see
  <https://github.com/neondatabase/serverless>. Postgrex by default
  binds parameters in **binary format**, so it refuses to encode
  `"42"` as `int4` (`DBConnection.EncodeError`).

  We resolve this server-side by:

    1. Running `Postgrex.prepare/3` against the SQL to get the inferred
       `param_oids` from Postgres.
    2. For each `(string_value, oid)` pair coercing the string into the
       expected Elixir term (`"42"` → `42` for int4 OID 23, etc.).

  Genuine JSON `null` round-trips to Elixir `nil` (SQL NULL).
  """

  # The OID constants we care to coerce explicitly. Everything else is
  # passed through as-is — Postgrex falls back to its default encoder
  # which is fine for text / unknown / `untyped` parameters.

  @bool 16
  @bytea 17
  @int8 20
  @int2 21
  @int4 23
  @text 25
  @float4 700
  @float8 701
  @varchar 1043
  @numeric 1700
  @date 1082
  @time 1083
  @timestamp 1114
  @timestamptz 1184
  @interval 1186
  @uuid 2950
  @json 114
  @jsonb 3802

  # Array OID → element OID. Mirrors Supavisor.HttpSql.ValueEncoder.
  @array_element %{
    1000 => @bool,
    1001 => @bytea,
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
  Coerce one parameter value for a given column OID.
  """
  @spec coerce(term, non_neg_integer | nil) :: term
  def coerce(nil, _oid), do: nil

  def coerce(v, oid) when oid in [@int2, @int4, @int8] and is_binary(v) do
    String.to_integer(v)
  end

  def coerce(v, oid) when oid in [@float4, @float8] and is_binary(v) do
    case v do
      "NaN" ->
        :nan

      "Infinity" ->
        :infinity

      "-Infinity" ->
        :negative_infinity

      _ ->
        # Float.parse returns {n, rest} — a non-empty `rest` means the
        # input wasn't a clean float (e.g. "3.14garbage" → {3.14, "garbage"}).
        # Reject those instead of silently accepting partial parses.
        case Float.parse(v) do
          {n, ""} -> n
          _ -> raise ArgumentError, "invalid float #{inspect(v)}"
        end
    end
  end

  def coerce(v, @bool) when is_binary(v) do
    case String.downcase(v) do
      x when x in ["t", "true", "1"] -> true
      x when x in ["f", "false", "0"] -> false
      _ -> raise ArgumentError, "cannot coerce #{inspect(v)} to bool"
    end
  end

  def coerce(v, @numeric) when is_binary(v) do
    Decimal.new(v)
  end

  def coerce("\\x" <> hex, @bytea), do: Base.decode16!(hex, case: :mixed)
  def coerce(v, @bytea) when is_binary(v), do: v

  def coerce(v, @date) when is_binary(v), do: Date.from_iso8601!(v)
  def coerce(v, @time) when is_binary(v), do: Time.from_iso8601!(v)

  def coerce(v, @timestamp) when is_binary(v) do
    v
    |> String.replace(" ", "T", global: false)
    |> NaiveDateTime.from_iso8601!()
  end

  def coerce(v, @timestamptz) when is_binary(v) do
    case DateTime.from_iso8601(String.replace(v, " ", "T", global: false)) do
      {:ok, dt, _offset} -> dt
      {:error, reason} -> raise ArgumentError, "invalid timestamptz #{inspect(v)}: #{reason}"
    end
  end

  def coerce(v, @uuid) when is_binary(v) and byte_size(v) == 36 do
    Ecto.UUID.dump!(v)
  end

  def coerce(v, oid) when oid in [@json, @jsonb] and is_binary(v) do
    Jason.decode!(v)
  end

  # Interval: accept ISO 8601 ("P1Y2M3DT4H5M6S") OR Postgres text
  # ("1 year 2 mons"). Postgrex.Interval struct is the expected binding
  # shape — round-trip via the same parser the type uses on the wire.
  def coerce(v, @interval) when is_binary(v) do
    # Postgrex doesn't expose a public Interval parser; we accept the
    # "<int> <unit>" comma-or-space text format that PG itself prints
    # back. Anything more exotic — fall through and let Postgrex try.
    parse_interval(v)
  end

  # Array params arrive from Neon as JSON arrays of strings. Coerce
  # each element by the element OID so Postgrex can bind the array.
  def coerce(v, array_oid) when is_list(v) and is_map_key(@array_element, array_oid) do
    element_oid = Map.fetch!(@array_element, array_oid)
    Enum.map(v, fn elem -> coerce(elem, element_oid) end)
  end

  # Native types passed by JSON: nothing to coerce.
  def coerce(v, _oid), do: v

  # ---------------------------------------------------------------------------

  # Minimal "<int> <unit> ..." parser. Anything more exotic (ISO 8601,
  # microsecond fractions, etc.) falls back to a zero-interval — caller
  # should send these in Postgrex.Interval-compatible JSON shapes if
  # they need precision.
  defp parse_interval(text) do
    %Postgrex.Interval{months: 0, days: 0, secs: 0, microsecs: 0}
    |> apply_interval_parts(String.split(text, [",", " "], trim: true))
  end

  defp apply_interval_parts(acc, []), do: acc

  defp apply_interval_parts(acc, [n, unit | rest]) do
    case Integer.parse(n) do
      {value, ""} -> apply_interval_parts(add_interval(acc, unit, value), rest)
      _ -> acc
    end
  end

  defp apply_interval_parts(acc, _), do: acc

  defp add_interval(%Postgrex.Interval{months: m} = i, unit, v)
       when unit in ~w(year years yr y),
       do: %{i | months: m + v * 12}

  defp add_interval(%Postgrex.Interval{months: m} = i, unit, v)
       when unit in ~w(mon mons month months),
       do: %{i | months: m + v}

  defp add_interval(%Postgrex.Interval{days: d} = i, unit, v)
       when unit in ~w(day days),
       do: %{i | days: d + v}

  defp add_interval(%Postgrex.Interval{secs: s} = i, unit, v)
       when unit in ~w(hour hours hr h),
       do: %{i | secs: s + v * 3600}

  defp add_interval(%Postgrex.Interval{secs: s} = i, unit, v)
       when unit in ~w(min mins minute minutes),
       do: %{i | secs: s + v * 60}

  defp add_interval(%Postgrex.Interval{secs: s} = i, unit, v)
       when unit in ~w(sec secs second seconds),
       do: %{i | secs: s + v}

  defp add_interval(i, _unit, _v), do: i

  @doc """
  Coerce a full list against a list of OIDs. Lists must be the same
  length; mismatched lengths fall back to identity.
  """
  @spec coerce_list([term], [non_neg_integer] | nil) :: [term]
  def coerce_list(params, nil), do: params

  def coerce_list(params, oids) when length(params) == length(oids) do
    Enum.zip(params, oids)
    |> Enum.map(fn {v, oid} -> coerce(v, oid) end)
  end

  def coerce_list(params, _oids), do: params
end
