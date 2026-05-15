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
        user: db_user_alias,
        password: plaintext_password,
        database: database,
        remote_ip: ip,
        request_id: request_id_or_nil,
        tenant: %Tenant{},
        user_record: %User{}
      }

  On failure: short-circuits with a Neon-shaped JSON error body via
  `Supavisor.HttpSql.ErrorMapper.to_neon_error/1` and halts the conn.
  """

  @behaviour Plug

  import Plug.Conn

  alias Supavisor.CircuitBreaker
  alias Supavisor.FeatureFlag
  alias Supavisor.HandlerHelpers
  alias Supavisor.HttpSql.{ConnString, ErrorMapper}
  alias Supavisor.Tenants

  @feature_flag_name "http_sql"

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    with :ok <- check_globally_enabled(),
         {:ok, url} <- read_header(conn),
         {:ok, parsed} <- parse_url(url),
         {:ok, %{user: user, tenant: tenant}} <- resolve_tenant(parsed),
         ip <- remote_ip(conn),
         :ok <- check_circuit_breaker(tenant.external_id, ip),
         :ok <- check_feature_flag(tenant),
         :ok <- check_allow_list(tenant, ip) do
      assign(conn, :http_sql_ctx, %{
        tenant_external_id: tenant.external_id,
        user: parsed.user,
        password: parsed.password,
        database: parsed.database || tenant.db_database,
        remote_ip: ip,
        request_id: get_req_header(conn, "x-request-id") |> List.first(),
        tenant: tenant,
        user_record: user
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

      {:error, %{__struct__: struct}} when struct == Supavisor.Errors.NoTenantIdentifierError ->
        {:error, {:malformed_request, "tenant identifier missing"}}

      {:error, %{__struct__: _}} ->
        {:error, {:unauthorized, "tenant or user not found"}}

      _ ->
        {:error, {:unauthorized, "tenant or user not found"}}
    end
  end

  defp check_circuit_breaker(external_id, ip) do
    case CircuitBreaker.check({external_id, ip}, :auth_error) do
      :ok -> :ok
      {:error, %{__struct__: _} = e} -> {:error, e}
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

  defp remote_ip(conn) do
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
