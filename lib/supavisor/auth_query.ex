defmodule Supavisor.AuthQuery do
  @moduledoc """
  Connects to an upstream PostgreSQL database and runs the auth query
  to fetch user secrets (SCRAM-SHA-256 or MD5).
  """

  alias Supavisor.ClientHandler.Auth.{ManagerSecrets, SASLSecrets}
  alias Supavisor.Errors.AuthQueryError
  alias Supavisor.Helpers
  alias Supavisor.Tenants.Tenant

  @doc """
  Starts and links a Postgrex connection configured for auth-query use.
  """
  @spec start_link(Tenant.t(), ManagerSecrets.t()) :: {:ok, pid()} | {:error, term()}
  def start_link(%Tenant{} = tenant, %ManagerSecrets{} = manager) do
    ssl_opts = build_ssl_options(tenant)
    ip_version = Helpers.ip_version(tenant.ip_version, tenant.db_host)

    Postgrex.start_link(
      hostname: tenant.db_host,
      port: tenant.db_port,
      database: tenant.db_database,
      password: manager.db_password,
      username: manager.db_user,
      parameters: [application_name: "Supavisor (auth_query)"],
      ssl: tenant.upstream_ssl,
      socket_options: [ip_version],
      queue_target: 1_000,
      queue_interval: 5_000,
      ssl_opts: ssl_opts
    )
  end

  @doc """
  Asynchronously stops a Postgrex connection. Spawns a process that attempts
  a normal stop with a 5-second timeout, then force-kills if that fails.
  """
  @spec stop_connection_async(pid()) :: :ok
  def stop_connection_async(conn) do
    Process.unlink(conn)

    spawn(fn ->
      try do
        GenServer.stop(conn, :normal, 5_000)
      catch
        :exit, _ -> Process.exit(conn, :kill)
      end
    end)

    :ok
  end

  @doc """
  Runs the auth query against a connection and parses the result into
  a `SASLSecrets` struct. MD5 secrets are rejected with an error.
  """
  @spec fetch_user_secret(pid(), String.t() | nil, String.t()) ::
          {:ok, SASLSecrets.t()} | {:error, AuthQueryError.t()}
  def fetch_user_secret(_conn, nil, _user) do
    {:error, %AuthQueryError{reason: :no_auth_query}}
  end

  def fetch_user_secret(conn, auth_query, user) when is_binary(auth_query) do
    Postgrex.query!(conn, auth_query, [user])
  catch
    _error, reason ->
      {:error, %AuthQueryError{reason: :query_failed, details: reason}}
  else
    %{columns: [_, _], rows: [[^user, secret]]} ->
      parse_secret(secret, user)

    %{columns: [_, _], rows: []} ->
      {:error, %AuthQueryError{reason: :user_not_found}}

    %{columns: columns} when is_list(columns) ->
      {:error, %AuthQueryError{reason: :wrong_format}}
  end

  @doc """
  Parses a PostgreSQL secret string (from `pg_authid.rolpassword`) into
  a `SASLSecrets` struct. MD5 secrets are rejected with an error.
  """
  @spec parse_secret(String.t(), String.t()) ::
          {:ok, SASLSecrets.t()} | {:error, AuthQueryError.t()}
  def parse_secret("SCRAM-SHA-256" <> _ = secret, user) do
    # <digest>$<iteration>:<salt>$<stored_key>:<server_key>
    case Regex.run(~r/^(.+)\$(\d+):(.+)\$(.+):(.+)$/, secret) do
      [_, digest, iterations, salt, stored_key, server_key] ->
        decoded_stored_key = Base.decode64!(stored_key)
        decoded_server_key = Base.decode64!(server_key)

        {:ok,
         %SASLSecrets{
           user: user,
           digest: digest,
           iterations: String.to_integer(iterations),
           salt: salt,
           stored_key: decoded_stored_key,
           client_key: decoded_stored_key,
           server_key: decoded_server_key
         }}

      _ ->
        {:error, %AuthQueryError{reason: :parse_error}}
    end
  end

  def parse_secret("md5" <> _secret, _user) do
    {:error, %AuthQueryError{reason: :md5_not_supported}}
  end

  def parse_secret(_secret, _user) do
    {:error, %AuthQueryError{reason: :unsupported_secret_format}}
  end

  ## Private

  defp build_ssl_options(%Tenant{upstream_ssl: true, upstream_verify: :peer} = tenant) do
    sni = tenant.sni_hostname || tenant.db_host

    [
      verify: :verify_peer,
      cacerts: [Helpers.upstream_cert(tenant.upstream_tls_ca)],
      server_name_indication: String.to_charlist(sni),
      customize_hostname_check: [{:match_fun, fn _, _ -> true end}]
    ]
  end

  defp build_ssl_options(_tenant) do
    [verify: :verify_none]
  end
end
