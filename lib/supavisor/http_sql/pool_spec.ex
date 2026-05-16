defmodule Supavisor.HttpSql.PoolSpec do
  @moduledoc """
  Builds the keyword list passed to `Postgrex.start_link/1` for the HTTP
  /sql per-`(tenant, user, password)` connection pool.

  We dial `127.0.0.1` on `proxy_port_transaction` so every HTTP-driven
  query traverses the existing `Supavisor.ClientHandler` → pool →
  `Supavisor.DbHandler` machinery, inheriting tenant routing, SCRAM auth,
  IP-ban recording, prepared-statement caching, and telemetry.
  """

  @doc """
  Build the start-link opts.

  Required keys in `ctx`:

    * `:user` — the Postgres role to authenticate as (e.g. `"postgres.dev_tenant"`)
    * `:password` — plaintext password (HTTP came over TLS at the LB)
    * `:database` — target database name (defaults to `"postgres"` if missing)

  Optional:

    * `:pool_size` (default from app config `:http_sql -> :pool_size`)
    * `:port` (default from `:supavisor -> :proxy_port_transaction`)
    * `:hostname` (default `"127.0.0.1"`)
    * `:request_timeout_ms` — used as both `timeout` and `connect_timeout`
  """
  @spec build(map) :: keyword
  def build(ctx) when is_map(ctx) do
    http_sql = Application.get_env(:supavisor, :http_sql, [])

    [
      hostname: Map.get(ctx, :hostname, "127.0.0.1"),
      port: Map.get(ctx, :port, Application.fetch_env!(:supavisor, :proxy_port_transaction)),
      username: Map.fetch!(ctx, :user),
      password: Map.fetch!(ctx, :password),
      database: Map.get(ctx, :database) || "postgres",
      pool_size: Map.get(ctx, :pool_size, Keyword.get(http_sql, :pool_size, 5)),
      # Override DBConnection's default `:rand_exp` with plain `:exp`.
      # This lets the pool self-heal across transient backend disconnects
      # (e.g. supavisor terminates its upstream pool when the tenant is
      # updated). Bad-password failures are bounded by the tenant-level
      # CircuitBreaker for :auth_error recorded by HttpSql.execute.
      backoff_type: :exp,
      show_sensitive_data_on_connection_error: false,
      parameters: [application_name: "supavisor-http-sql"],
      timeout: Map.get(ctx, :request_timeout_ms, Keyword.get(http_sql, :request_timeout_ms, 30_000)),
      connect_timeout:
        Map.get(ctx, :request_timeout_ms, Keyword.get(http_sql, :request_timeout_ms, 30_000))
    ]
  end

  @doc """
  Deterministic key used to look up an existing pool in the registry. The
  password hash is included so that a password rotation naturally lands in
  a new pool while the old one drains.
  """
  @spec key(String.t() | nil, String.t(), String.t()) :: tuple()
  def key(tenant_external_id, user, password) do
    {tenant_external_id, user, :crypto.hash(:sha256, password)}
  end
end
