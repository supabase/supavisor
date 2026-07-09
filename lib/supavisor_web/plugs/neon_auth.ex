defmodule SupavisorWeb.Plugs.NeonAuth do
  @moduledoc """
  Plug that resolves the tenant/user for an HTTP /sql request from the
  `Neon-Connection-String` header and gates on:

    1. Global feature flag (`:supavisor, :http_sql, :enabled`)
    2. Header presence + URL parseability
    3. Tenant + user lookup via `Supavisor.Tenants.get_user_cache/4`
    4. IP-ban via `Supavisor.CircuitBreaker.check({external_id, ip}, :auth_error)`
    5. Per-tenant feature flag `feature_flags["http_sql"]`
    6. Tenant `allow_list` CIDR match via `Supavisor.HandlerHelpers.filter_cidrs/2`

  On success assigns:

      conn.assigns.http_sql_ctx = %{
        tenant_external_id: external_id,
        user: full_user_with_external_id,    # e.g. "postgres.acme"
        db_user: db_role,                    # e.g. "postgres"  (the role on Postgres side)
        password: plaintext_password,
        database: database,
        remote_ip: ip,
        request_id: request_id_or_nil
      }

  On failure: short-circuits with a Neon-shaped JSON error body via
  `Supavisor.HttpSql.ErrorMapper.to_neon_error/1` and halts the conn.
  """

  @behaviour Plug

  import Plug.Conn

  alias Supavisor.CircuitBreaker
  alias Supavisor.FeatureFlag
  alias Supavisor.HandlerHelpers
  alias Supavisor.HttpSql.{ConnString, ErrorMapper, PasswordVerifier}
  alias Supavisor.Tenants

  @feature_flag_name "http_sql"

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    with :ok <- check_globally_enabled(),
         :ok <- reject_jwt_auth(conn),
         {:ok, url} <- read_header(conn),
         {:ok, parsed} <- parse_url(url),
         {:ok, %{user: user, tenant: tenant}} <- resolve_tenant(parsed),
         ip <- remote_ip(conn),
         :ok <- check_circuit_breaker(tenant.external_id, ip),
         :ok <- check_feature_flag(tenant),
         :ok <- check_allow_list(tenant, ip),
         :ok <- verify_password(tenant, user, parsed.password, ip) do
      assign(conn, :http_sql_ctx, %{
        tenant_external_id: tenant.external_id,
        user: parsed.user,
        db_user: user.db_user,
        password: parsed.password,
        database: parsed.database || tenant.db_database,
        remote_ip: ip,
        request_id: get_req_header(conn, "x-request-id") |> List.first()
      })
    else
      {:error, term} -> halt_with_error(conn, term)
    end
  end

  # ---------------------------------------------------------------------------

  defp check_globally_enabled do
    enabled? =
      Application.get_env(:supavisor, :http_sql, [])
      |> Keyword.get(:enabled, false)

    if enabled?, do: :ok, else: {:error, {:feature_disabled, :global}}
  end

  defp read_header(conn) do
    case get_req_header(conn, "neon-connection-string") do
      [url | _] when is_binary(url) and url != "" -> {:ok, url}
      _ -> {:error, {:malformed_request, "missing Neon-Connection-String header"}}
    end
  end

  # The @neondatabase/serverless driver sets Authorization: Bearer <jwt>
  # when the caller configured an authToken (Neon's RLS path). We do NOT
  # support JWT auth in v1 — fail loudly rather than silently treat the
  # password as sole authentication, otherwise a user expecting JWT
  # verification would think their token is being checked.
  defp reject_jwt_auth(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> _ | _] ->
        {:error,
         {:unauthorized,
          "JWT authentication is not supported on /sql; use Neon-Connection-String"}}

      _ ->
        :ok
    end
  end

  defp parse_url(url) do
    case ConnString.parse(url) do
      {:ok, _} = ok -> ok
      {:error, reason} -> {:error, {:malformed_request, reason}}
    end
  end

  defp resolve_tenant(parsed) do
    # The full URL username carries `<role>.<external_id>` per Supabase
    # convention. Tenants.get_user_cache/4 expects the role-only part.
    db_user =
      case String.split(parsed.user, ".", parts: 2) do
        [role, _ext_id] -> role
        [role] -> role
      end

    case Tenants.get_user_cache(:single, db_user, parsed.external_id, nil) do
      {:ok, %{user: _, tenant: _}} = ok ->
        ok

      {:error, %Supavisor.Errors.NoTenantIdentifierError{}} ->
        {:error, {:malformed_request, "tenant identifier missing"}}

      {:error, _} ->
        {:error, {:unauthorized, "tenant or user not found"}}
    end
  end

  defp check_circuit_breaker(external_id, ip) do
    case CircuitBreaker.check({external_id, ip}, :auth_error) do
      :ok -> :ok
      {:error, %{__struct__: _} = e} -> {:error, e}
    end
  end

  # Synchronously verify the password against cached SASL secrets BEFORE
  # checking out a Postgrex pool. Two reasons this lives here and not in
  # the facade:
  #
  #   1. Bad passwords never spin up a Postgrex pool — no churn, no
  #      ConnectionError/timeout cascade that hides the auth-fail signal.
  #   2. The CircuitBreaker tick is recorded against the real HTTP
  #      caller IP, not the loopback peer of our Postgrex pool. Without
  #      this, brute-force defense would have been unreliable (see
  #      Agent #3 security review CRIT-8 on the original design).
  defp verify_password(tenant, user, password, ip) do
    case PasswordVerifier.verify(tenant, user, password) do
      :ok ->
        :ok

      {:error, :invalid_password} ->
        if ip, do: CircuitBreaker.record_failure({tenant.external_id, ip}, :auth_error)
        {:error, {:unauthorized, "invalid password"}}

      {:error, _reason} ->
        # Validation secrets are temporarily unavailable (e.g. auth_query
        # path with upstream Postgres unreachable). Do NOT record a
        # CircuitBreaker tick — this isn't the client's fault. Fail open
        # to a 503 so the operator can spot the upstream issue.
        {:error, %DBConnection.ConnectionError{message: "auth secrets unavailable"}}
    end
  end

  defp check_feature_flag(tenant) do
    if FeatureFlag.enabled?(tenant, @feature_flag_name) do
      :ok
    else
      {:error, {:feature_disabled, :tenant}}
    end
  end

  defp check_allow_list(_tenant, nil), do: {:error, {:forbidden, "ip_unknown"}}

  defp check_allow_list(tenant, ip) do
    case HandlerHelpers.filter_cidrs(tenant.allow_list || [], ip) do
      [] -> {:error, {:forbidden, "ip_not_allowed"}}
      [_ | _] -> :ok
    end
  end

  # Trust X-Forwarded-For ONLY when the immediate peer (conn.remote_ip)
  # is in the configured trusted-proxy CIDR list. Without this gate, any
  # client can spoof their source IP via the XFF header and bypass
  # tenant `allow_list` / CircuitBreaker IP-bans.
  defp remote_ip(conn) do
    if trusted_peer?(conn.remote_ip) do
      case get_req_header(conn, "x-forwarded-for") do
        [chain | _] when is_binary(chain) ->
          chain
          |> String.split(",")
          |> List.first()
          |> String.trim()
          |> parse_ip()

        _ ->
          conn.remote_ip
      end
    else
      conn.remote_ip
    end
  end

  defp trusted_peer?(nil), do: false

  defp trusted_peer?(ip) do
    cidrs =
      Application.get_env(:supavisor, :http_sql, [])
      |> Keyword.get(:trusted_proxies, [])

    case cidrs do
      [] -> false
      list -> HandlerHelpers.filter_cidrs(list, ip) != []
    end
  end

  defp parse_ip(str) when is_binary(str) do
    case :inet.parse_address(String.to_charlist(str)) do
      {:ok, ip} -> ip
      _ -> nil
    end
  end

  defp parse_ip(_), do: nil

  defp halt_with_error(conn, term) do
    {status, body} = ErrorMapper.to_neon_error(term)

    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(body))
    |> halt()
  end
end
