defmodule Supavisor.HttpSql.PgError do
  @moduledoc """
  In-memory representation of a Postgres `ErrorResponse` decoded from the
  backend wire stream by `Supavisor.HttpSql.WireDecoder`.

  The `fields` map mirrors the single-letter ErrorResponse field codes used by
  the protocol (`"S"`, `"V"`, `"C"`, `"M"`, `"D"`, `"H"`, `"P"`, `"p"`, `"q"`,
  `"W"`, `"s"`, `"t"`, `"c"`, `"d"`, `"n"`, `"F"`, `"L"`, `"R"`). The shape is
  intentionally the same as `%Postgrex.Error{postgres: %{...}}` so that
  `Supavisor.HttpSql.ErrorMapper` can map both with similar clauses.

  `code` and `message` are pulled out for fast pattern matching; the full
  `fields` map is kept for the response body builder.
  """

  defexception [:code, :severity, :message, :fields]

  @type t :: %__MODULE__{
          code: String.t() | nil,
          severity: String.t() | nil,
          message: String.t() | nil,
          fields: %{optional(String.t()) => String.t()}
        }

  @impl true
  def exception(fields) when is_map(fields) do
    %__MODULE__{
      code: Map.get(fields, "C"),
      severity: Map.get(fields, "S") || Map.get(fields, "V"),
      message: Map.get(fields, "M"),
      fields: fields
    }
  end

  @impl true
  def message(%__MODULE__{message: m, code: c}) when is_binary(m) and is_binary(c) do
    "(#{c}) #{m}"
  end

  def message(%__MODULE__{message: m}) when is_binary(m), do: m
  def message(_), do: "unknown postgres error"
end
