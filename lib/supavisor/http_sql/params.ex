defmodule Supavisor.HttpSql.Params do
  @moduledoc """
  Stringification of HTTP /sql request parameters into PostgreSQL text format.

  The Neon JSON body delivers parameter values as native JSON scalars (numbers,
  booleans, strings, null). `Supavisor.HttpSql.Wire.bind/3` sends every
  parameter with format code 0 (text), which means the backend parses each
  value from its PostgreSQL text representation. This module is the bridge —
  it turns Elixir terms into those text representations.

  ## Conversions

      nil                 → SQL NULL (kept as nil for `Wire.bind/3`)
      true / false        → "t" / "f"            (Postgres boolean input)
      integer             → "<int>"
      float               → "<float>"
      :nan / :infinity / :negative_infinity
                          → "NaN" / "Infinity" / "-Infinity"
      atom (other)        → Atom.to_string/1
      binary              → passthrough          (already a string)
      list / map (other)  → Jason.encode!/1     (json input)

  Lists/maps are JSON-encoded as a best-effort: they only make sense for
  `json`/`jsonb` parameter columns (Postgres will reject for other types).
  """

  @type param :: term()

  @doc """
  Convert a single Elixir term to its PostgreSQL text representation.
  `nil` is preserved (passed through to `Wire.bind/3` as the SQL NULL signal).
  """
  @spec stringify(param()) :: binary() | nil
  def stringify(nil), do: nil
  def stringify(bin) when is_binary(bin), do: bin
  def stringify(true), do: "t"
  def stringify(false), do: "f"
  def stringify(n) when is_integer(n), do: Integer.to_string(n)

  def stringify(n) when is_float(n), do: Float.to_string(n)
  def stringify(:nan), do: "NaN"
  def stringify(:infinity), do: "Infinity"
  def stringify(:negative_infinity), do: "-Infinity"

  def stringify(a) when is_atom(a), do: Atom.to_string(a)
  def stringify(other), do: Jason.encode!(other)

  @doc """
  Convert a list of Elixir terms to a list of PostgreSQL text strings (or nils).
  """
  @spec stringify_list([param()]) :: [binary() | nil]
  def stringify_list(params) when is_list(params), do: Enum.map(params, &stringify/1)
end
