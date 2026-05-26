defmodule Supavisor.HttpSql.ErrorMapper do
  @moduledoc """
  Maps Elixir-side errors raised during HTTP /sql execution to the
  Neon-driver-compatible JSON error body and an HTTP status code.

  The `@neondatabase/serverless` client reads `code`, `severity`, `detail`,
  `hint`, `position`, `internalQuery`, `where`, `schema`, `table`, `column`,
  `dataType`, `constraint`, `file`, `line`, `routine` off the response body
  and re-throws them on `NeonDbError`. Mirror those field names exactly so
  existing `pg`-style error handling on the client just works.

  ## Mapping table

  | Term                                                      | HTTP | code              |
  |-----------------------------------------------------------|------|-------------------|
  | `%PgError{code: "28P01"\|"28000"}`                        | 401  | upstream SQLSTATE |
  | `%PgError{code: "42501"}`                                 | 403  | `"42501"`         |
  | `%PgError{code: _}`                                       | 400  | upstream SQLSTATE |
  | `%DBConnection.ConnectionError{}` / `:timeout`            | 503  | `"connection_error"` |
  | `%Supavisor.Errors.CircuitBreakerError{}`                 | 503  | `"circuit_open"`  |
  | `{:row_limit_exceeded, n}`                                | 413  | `"row_limit_exceeded"` |
  | `{:params_encoding, reason}`                              | 400  | `"params_encoding"` |
  | `{:malformed_request, reason}`                            | 400  | `"malformed_request"` |
  | other / unknown                                           | 500  | `"internal_error"` |
  """

  alias Supavisor.Errors.CircuitBreakerError
  alias Supavisor.HttpSql.PgError

  @type body :: %{optional(String.t()) => term()}
  @type result :: {status :: pos_integer, body}

  @doc """
  Map an arbitrary error term to `{http_status, neon_error_body}`.
  """
  @spec to_neon_error(term) :: result
  def to_neon_error(error)

  # ---------------- PgError (Supavisor wire decoder) ----------------

  def to_neon_error(%PgError{} = err) do
    status = pg_status_from_code(err.code)
    {status, pg_error_to_body(err)}
  end

  # ---------------- DBConnection / timeouts ----------------

  def to_neon_error(%DBConnection.ConnectionError{message: msg}) do
    {503, %{"message" => msg || "connection error", "code" => "connection_error"}}
  end

  def to_neon_error(:timeout) do
    {503, %{"message" => "request timed out", "code" => "timeout"}}
  end

  # ---------------- Circuit breaker ----------------

  def to_neon_error(%CircuitBreakerError{operation: op, blocked_until: until}) do
    {503,
     %{
       "message" => "circuit breaker open for operation: #{op}",
       "code" => "circuit_open",
       "operation" => to_string(op),
       "blocked_until" => format_blocked_until(until)
     }}
  end

  # ---------------- Application-level errors ----------------

  def to_neon_error({:row_limit_exceeded, limit}) do
    {413,
     %{
       "message" => "result set exceeds row limit (#{limit})",
       "code" => "row_limit_exceeded",
       "limit" => limit
     }}
  end

  def to_neon_error({:response_too_large, %{limit: limit, size: size}}) do
    {413,
     %{
       "message" => "serialized response (#{size} bytes) exceeds size limit (#{limit})",
       "code" => "response_too_large",
       "limit" => limit,
       "size" => size
     }}
  end

  def to_neon_error({:params_encoding, reason}) do
    {400,
     %{
       "message" => "failed to encode query parameters: #{inspect(reason)}",
       "code" => "params_encoding"
     }}
  end

  def to_neon_error({:malformed_request, reason}) do
    {400,
     %{"message" => "malformed request: #{to_string(reason)}", "code" => "malformed_request"}}
  end

  def to_neon_error({:unauthorized, reason}) do
    {401, %{"message" => to_string(reason), "code" => "unauthorized"}}
  end

  def to_neon_error({:forbidden, reason}) do
    {403, %{"message" => to_string(reason), "code" => to_string(reason)}}
  end

  def to_neon_error({:feature_disabled, _}) do
    {404, %{"message" => "endpoint not enabled", "code" => "feature_disabled"}}
  end

  # ---------------- Fallback ----------------

  # IMPORTANT: never `inspect/2` an arbitrary term into the response body.
  # Unknown error structs can carry conns, auth tokens, internal stack
  # traces, or other sensitive payload. Emit a generic message and log
  # the actual term with a `Logger.warning` for ops triage.
  def to_neon_error(other) do
    require Logger

    Logger.warning(
      "HttpSql: unmapped error: #{inspect(other, limit: :infinity, printable_limit: 500)}"
    )

    {500, %{"message" => "internal error", "code" => "internal_error"}}
  end

  # ---------------------------------------------------------------------------

  # Map a 5-character SQLSTATE to an HTTP status. Mirrors the Postgrex.Error
  # branch above but works on raw strings from the wire.
  defp pg_status_from_code("28P01"), do: 401
  defp pg_status_from_code("28000"), do: 401
  defp pg_status_from_code("42501"), do: 403
  defp pg_status_from_code(_), do: 400

  # Translate the single-letter ErrorResponse field codes into the camelCase
  # keys the @neondatabase/serverless driver expects. See:
  # https://www.postgresql.org/docs/current/protocol-error-fields.html
  defp pg_error_to_body(%PgError{fields: fields}) do
    %{
      "message" => Map.get(fields, "M", "database error"),
      "code" => Map.get(fields, "C"),
      "severity" => Map.get(fields, "S") || Map.get(fields, "V"),
      "detail" => Map.get(fields, "D"),
      "hint" => Map.get(fields, "H"),
      "position" => Map.get(fields, "P"),
      "internalPosition" => Map.get(fields, "p"),
      "internalQuery" => Map.get(fields, "q"),
      "where" => Map.get(fields, "W"),
      "schema" => Map.get(fields, "s"),
      "table" => Map.get(fields, "t"),
      "column" => Map.get(fields, "c"),
      "dataType" => Map.get(fields, "d"),
      "constraint" => Map.get(fields, "n"),
      "file" => Map.get(fields, "F"),
      "line" => Map.get(fields, "L"),
      "routine" => Map.get(fields, "R")
    }
    |> drop_nils()
  end

  defp format_blocked_until(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_blocked_until(other), do: to_string(other)

  defp drop_nils(map) do
    for {k, v} <- map, v != nil, into: %{}, do: {k, v}
  end
end
