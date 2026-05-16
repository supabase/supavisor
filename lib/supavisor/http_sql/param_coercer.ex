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
  @float4 700
  @float8 701
  @numeric 1700
  @date 1082
  @time 1083
  @timestamp 1114
  @timestamptz 1184
  @uuid 2950
  @json 114
  @jsonb 3802

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
      "NaN" -> :nan
      "Infinity" -> :infinity
      "-Infinity" -> :negative_infinity
      _ -> elem(Float.parse(v), 0)
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

  # Native types passed by JSON: nothing to coerce.
  def coerce(v, _oid), do: v

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
