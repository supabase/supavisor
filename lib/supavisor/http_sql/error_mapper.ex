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
  | `%Postgrex.Error{postgres: %{code: :invalid_password}}`   | 401  | `"28P01"`         |
  | `%Postgrex.Error{postgres: %{code: <auth-spec>}}`         | 401  | upstream code     |
  | `%Postgrex.Error{postgres: <other>}`                      | 400  | upstream code     |
  | `%DBConnection.ConnectionError{}` / `:timeout`            | 503  | `"connection_error"` |
  | `%Supavisor.Errors.CircuitBreakerError{}`                 | 503  | `"circuit_open"`  |
  | `{:row_limit_exceeded, n}`                                | 413  | `"row_limit_exceeded"` |
  | `{:params_encoding, reason}`                              | 400  | `"params_encoding"` |
  | `{:malformed_request, reason}`                            | 400  | `"malformed_request"` |
  | other / unknown                                           | 500  | `"internal_error"` |
  """

  alias Supavisor.Errors.CircuitBreakerError

  @type body :: %{optional(String.t()) => term()}
  @type result :: {status :: pos_integer, body}

  @doc """
  Map an arbitrary error term to `{http_status, neon_error_body}`.
  """
  @spec to_neon_error(term) :: result
  def to_neon_error(error)

  # ---------------- Postgrex ----------------

  def to_neon_error(%Postgrex.Error{postgres: %{code: code} = pg}) when is_map(pg) do
    status =
      cond do
        code in [:invalid_password, :invalid_authorization_specification] -> 401
        code == :insufficient_privilege -> 403
        true -> 400
      end

    {status, pg_to_body(pg)}
  end

  def to_neon_error(%Postgrex.Error{message: message}) do
    {500, %{"message" => message || "database error", "code" => "internal_error"}}
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

  def to_neon_error(other) do
    {500,
     %{
       "message" => "internal error",
       "code" => "internal_error",
       "detail" => inspect(other, limit: 200)
     }}
  end

  # ---------------------------------------------------------------------------

  defp pg_to_body(pg) do
    %{
      "message" => Map.get(pg, :message, "database error"),
      "code" => Map.get(pg, :pg_code) || atom_or_string(Map.get(pg, :code)),
      "severity" => Map.get(pg, :severity),
      "detail" => Map.get(pg, :detail),
      "hint" => Map.get(pg, :hint),
      "position" => Map.get(pg, :position),
      "internalPosition" => Map.get(pg, :internal_position),
      "internalQuery" => Map.get(pg, :internal_query),
      "where" => Map.get(pg, :where),
      "schema" => Map.get(pg, :schema),
      "table" => Map.get(pg, :table),
      "column" => Map.get(pg, :column),
      "dataType" => Map.get(pg, :data_type),
      "constraint" => Map.get(pg, :constraint),
      "file" => Map.get(pg, :file),
      "line" => Map.get(pg, :line),
      "routine" => Map.get(pg, :routine)
    }
    |> drop_nils()
  end

  defp atom_or_string(nil), do: nil
  defp atom_or_string(a) when is_atom(a), do: Atom.to_string(a)
  defp atom_or_string(s) when is_binary(s), do: s

  defp format_blocked_until(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_blocked_until(other), do: to_string(other)

  defp drop_nils(map) do
    for {k, v} <- map, v != nil, into: %{}, do: {k, v}
  end
end
