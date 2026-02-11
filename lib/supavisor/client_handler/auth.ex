defmodule Supavisor.ClientHandler.Auth do
  @moduledoc """
  Authentication logic for client connections.

  This module handles all authentication-related business logic including:
  - Secret retrieval and caching
  - Credential validation for different auth methods (MD5, SCRAM)
  - Authentication challenge preparation
  - Retry logic for failed authentications
  """

  require Logger

  alias Supavisor.{Helpers, Protocol.Server}
  alias Supavisor.ClientHandler.Auth.{MD5Secrets, PasswordSecrets, SASLSecrets}

  @type auth_method :: :password | :auth_query | :auth_query_md5
  @type auth_secrets :: {auth_method(), function()}

  ## Secret Management

  @doc """
  Retrieves authentication secrets for a user, with caching support.

  For password auth (require_user: true), returns password-based secrets.
  For auth_query, uses cache with TTL or fetches from database.
  """
  @spec get_user_secrets(Supavisor.id(), map(), String.t(), String.t()) ::
          {:ok, auth_secrets()} | {:error, term()}
  def get_user_secrets(
        _id,
        %{user: user, tenant: %{require_user: true}},
        _db_user,
        _tenant_or_alias
      ) do
    secrets = %PasswordSecrets{
      user: user.db_user,
      password: user.db_password
    }

    {:ok, {:password, fn -> secrets end}}
  end

  def get_user_secrets(id, info, db_user, tenant_or_alias) do
    fetch_fn = fn ->
      fetch_secrets_from_database(id, info, db_user)
    end

    Supavisor.SecretCache.fetch_validation_secrets(tenant_or_alias, db_user, fetch_fn)
  end

  ## Authentication Validation

  @doc """
  Validates authentication credentials based on the method.

  Supports password, auth_query, and auth_query_md5 methods.
  Returns {:ok, client_key} on success or {:error, reason} on failure.
  """
  @spec validate_credentials(auth_method(), term(), term(), term()) ::
          {:ok, binary() | nil} | {:error, :wrong_password}
  def validate_credentials(:password, _secrets, signatures, client_proof) do
    if client_proof == signatures.client,
      do: {:ok, nil},
      else: {:error, :wrong_password}
  end

  def validate_credentials(:auth_query, secrets, signatures, client_proof) do
    client_key = :crypto.exor(Base.decode64!(client_proof), signatures.client)

    if Helpers.hash(client_key) == secrets.().stored_key do
      {:ok, client_key}
    else
      {:error, :wrong_password}
    end
  end

  def validate_credentials(:auth_query_md5, server_hash, salt, client_hash) do
    expected_hash = "md5" <> Helpers.md5([server_hash, salt])

    if expected_hash == client_hash,
      do: {:ok, nil},
      else: {:error, :wrong_password}
  end

  ## Challenge Preparation

  @doc """
  Prepares authentication challenge data for SCRAM-based authentication.

  Generates the initial server message and signatures needed for the auth exchange.
  """
  @spec prepare_auth_challenge(auth_method(), function(), binary(), binary(), binary()) ::
          {binary(), map()}
  def prepare_auth_challenge(:password, secret_fn, nonce, user, channel) do
    message = Server.exchange_first_message(nonce)
    server_first_parts = Helpers.parse_server_first(message, nonce)

    {client_final_message, server_proof} =
      Helpers.get_client_final(
        :password,
        secret_fn.(),
        server_first_parts,
        nonce,
        user,
        channel
      )

    signatures = %{
      client: List.last(client_final_message),
      server: server_proof
    }

    {message, signatures}
  end

  def prepare_auth_challenge(:auth_query, secret_fn, nonce, user, channel) do
    secret = secret_fn.()
    message = Server.exchange_first_message(nonce, secret.salt)
    server_first_parts = Helpers.parse_server_first(message, nonce)

    signatures =
      Helpers.signatures(
        secret.stored_key,
        secret.server_key,
        server_first_parts,
        nonce,
        user,
        channel
      )

    {message, signatures}
  end

  ## Cache Update Logic (No Retry)

  @doc """
  Checks if secrets have changed and updates cache if needed

  This is used to detect password changes and refresh the cache (and the pool)
  for future connections
  """
  @spec check_and_update_secrets(
          auth_method(),
          term(),
          Supavisor.id(),
          map(),
          String.t(),
          String.t(),
          function()
        ) :: :ok
  def check_and_update_secrets(method, reason, client_id, info, tenant, user, current_secrets_fn) do
    if method != :password and reason == :wrong_password and
         not Supavisor.CacheRefreshLimiter.cache_refresh_limited?(client_id) do
      case fetch_secrets_from_database(client_id, info, user) do
        {:ok, {method2, secrets2}} ->
          current_secrets = current_secrets_fn.()
          new_secrets = secrets2.()

          if method != method2 or
               Map.delete(current_secrets, :client_key) != Map.delete(new_secrets, :client_key) do
            Logger.warning("ClientHandler: Update secrets")
            Supavisor.SecretCache.put_validation_secrets(tenant, user, method2, secrets2)
          end

        other ->
          Logger.error("ClientHandler: Auth secrets check error: #{inspect(other)}")
      end
    else
      Logger.debug("ClientHandler: No cache check needed")
    end

    :ok
  end

  ## Message Parsing

  @doc """
  Parses authentication response packets for different auth methods.

  Returns parsed credentials or error information.
  """
  @spec parse_auth_message(binary(), auth_method()) ::
          {:ok, term()} | {:error, term()}
  def parse_auth_message(bin, :auth_query_md5) do
    case Server.decode_pkt(bin) do
      {:ok, %{tag: :password_message, payload: {:md5, client_md5}}, _} ->
        {:ok, client_md5}

      {:error, error} ->
        {:error, {:decode_error, error}}

      other ->
        {:error, {:unexpected_message, other}}
    end
  end

  def parse_auth_message(bin, _scram_method) do
    case Server.decode_pkt(bin) do
      {:ok,
       %{
         tag: :password_message,
         payload: {:scram_sha_256, %{"n" => user, "r" => nonce, "c" => channel}}
       }, _} ->
        {:ok, {user, nonce, channel}}

      {:ok, %{tag: :password_message, payload: {:first_msg_response, %{"p" => p}}}, _} ->
        {:ok, p}

      {:error, error} ->
        {:error, {:decode_error, error}}

      other ->
        {:error, {:unexpected_message, other}}
    end
  end

  ## Authentication Context Management

  @doc """
  Creates initial authentication context for a given method and secrets.
  """
  @spec create_auth_context(auth_method(), function(), map()) :: map()
  def create_auth_context(:auth_query_md5, secrets, info) do
    salt = :crypto.strong_rand_bytes(4)

    %{
      method: :auth_query_md5,
      secrets: secrets,
      salt: salt,
      info: info,
      signatures: nil
    }
  end

  def create_auth_context(method, secrets, info) when method in [:password, :auth_query] do
    %{
      method: method,
      secrets: secrets,
      info: info,
      signatures: nil
    }
  end

  @doc """
  Updates authentication context with new signatures after challenge exchange.
  """
  @spec update_auth_context_with_signatures(map(), map()) :: map()
  def update_auth_context_with_signatures(auth_context, signatures) do
    %{auth_context | signatures: signatures}
  end

  ## Success Response Preparation

  @doc """
  Builds the final SCRAM response message for successful authentication.

  Takes the auth context and returns the complete protocol message to send.
  """
  @spec build_scram_final_response(map()) :: iodata()
  def build_scram_final_response(%{signatures: %{server: server_signature}}) do
    message = "v=#{Base.encode64(server_signature)}"
    Server.exchange_message(:final, message)
  end

  @doc """
  Prepares final secrets after successful authentication.

  Adds client_key to secrets if provided, otherwise returns original secrets.
  """
  @spec prepare_final_secrets(function(), binary() | nil) :: function()
  def prepare_final_secrets(secrets_fn, nil), do: secrets_fn

  def prepare_final_secrets(secrets_fn, client_key) do
    fn -> Map.put(secrets_fn.(), :client_key, client_key) end
  end

  ## Private Helpers

  @spec fetch_secrets_from_database(Supavisor.id(), map(), String.t()) ::
          {:ok, auth_secrets()} | {:error, term()}
  defp fetch_secrets_from_database(id, %{user: user, tenant: tenant}, db_user) do
    case Supavisor.SecretChecker.get_secrets(id) do
      {:error, :not_started} ->
        Logger.info(
          "ClientHandler: secret checker not started, starting a new database connection"
        )

        ssl_opts = build_ssl_options(tenant)

        {:ok, conn} =
          Postgrex.start_link(
            hostname: tenant.db_host,
            port: tenant.db_port,
            database: tenant.db_database,
            password: user.db_password,
            username: user.db_user,
            parameters: [application_name: "Supavisor auth_query"],
            ssl: tenant.upstream_ssl,
            socket_options: [
              Helpers.ip_version(tenant.ip_version, tenant.db_host)
            ],
            queue_target: 1_000,
            queue_interval: 5_000,
            ssl_opts: ssl_opts
          )

        try do
          Logger.debug(
            "ClientHandler: Connected to db #{tenant.db_host} #{tenant.db_port} #{tenant.db_database} #{user.db_user}"
          )

          with {:ok, secret} <- Helpers.get_user_secret(conn, tenant.auth_query, db_user) do
            auth_type =
              case secret do
                %MD5Secrets{} -> :auth_query_md5
                %SASLSecrets{} -> :auth_query
              end

            {:ok, {auth_type, fn -> secret end}}
          end
        rescue
          exception ->
            Logger.error("ClientHandler: Couldn't fetch user secrets from #{tenant.db_host}")
            reraise exception, __STACKTRACE__
        after
          Process.unlink(conn)

          spawn(fn ->
            try do
              GenServer.stop(conn, :normal, 5_000)
            catch
              :exit, _ -> Process.exit(conn, :kill)
            end
          end)
        end

      secrets ->
        secrets
    end
  end

  defp build_ssl_options(%{upstream_ssl: true, upstream_verify: :peer} = tenant) do
    [
      verify: :verify_peer,
      cacerts: [Helpers.upstream_cert(tenant.upstream_tls_ca)],
      server_name_indication: String.to_charlist(tenant.db_host),
      customize_hostname_check: [{:match_fun, fn _, _ -> true end}]
    ]
  end

  defp build_ssl_options(_tenant) do
    [verify: :verify_none]
  end
end
