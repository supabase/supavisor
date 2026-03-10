defmodule Supavisor.ClientHandler.Auth.ValidationSecrets do
  @moduledoc """
  Wraps the secrets used to validate incoming client authentication.

  Contains both SASL secrets (from the upstream database) and password secrets
  if available.

  Use `from_sasl_secrets/1` and `from_password_secrets/1` to construct instances
  instead of building the struct directly, to ensure `sasl_secrets` is always populated.
  """

  require Logger

  alias Supavisor.AuthQuery
  alias Supavisor.ClientHandler.Auth.{ManagerSecrets, PasswordSecrets, SASLSecrets}
  alias Supavisor.ClientHandler.Auth.Password
  alias Supavisor.ClientHandler.Auth.SCRAM

  @type t :: %__MODULE__{
          sasl_secrets: SASLSecrets.t(),
          password_secrets: PasswordSecrets.t() | nil
        }

  defstruct [:sasl_secrets, :password_secrets]

  @doc """
  Creates a `ValidationSecrets` from SASL secrets (fetched from upstream via auth_query).
  """
  @spec from_sasl_secrets(SASLSecrets.t()) :: t()
  def from_sasl_secrets(%SASLSecrets{} = sasl_secrets) do
    %__MODULE__{sasl_secrets: sasl_secrets}
  end

  @doc """
  Creates a `ValidationSecrets` from a `PasswordSecrets` struct.

  Derives SASL secrets from the plaintext password so that both SCRAM and
  password authentication work against the same cached entry.
  """
  @spec from_password_secrets(PasswordSecrets.t()) :: t()
  def from_password_secrets(%PasswordSecrets{} = password_secrets) do
    %__MODULE__{
      password_secrets: password_secrets,
      sasl_secrets: sasl_secrets_from_password(password_secrets.user, password_secrets.password)
    }
  end

  @doc """
  Fetches validation secrets

  If the tenant has `require_user: true`, the secrets from the user record are used.
  If the tenant has `require_user: false`, the secrets are fetched from the auth query,

  Uses the cache when possible. If there's no cache entry, `Cachex.fetch` avoids
  parallelization/excessive work.
  """
  def fetch_validation_secrets(_id, %{require_user: true} = tenant, user, db_user) do
    # Even though this is pure computation, we cache for memoization. Computing the
    # SASL secrets from the password can be CPU expensive.
    fetch_fn = fn ->
      {:ok,
       from_password_secrets(%PasswordSecrets{
         user: db_user,
         password: user.db_password
       })}
    end

    Supavisor.SecretCache.fetch_validation_secrets(tenant.external_id, db_user, fetch_fn)
  end

  def fetch_validation_secrets(id, tenant, user, db_user) do
    fetch_fn = fn ->
      fetch_secrets_from_database(id, tenant, user, db_user)
    end

    Supavisor.SecretCache.fetch_validation_secrets(tenant.external_id, db_user, fetch_fn)
  end

  @doc """
  Checks if the validation secrets have changed and updates them if necessary.

  Can be called after authentication fails, to check whether the secrets may
  be stale. Uses `CacheRefreshLimiter` to avoid excessive database queries.

  Only tenants with `require_user = false` have their validation secrets updated.
  Tenants with `require_user = true` must explicitly update their secrets through
  the API.
  """
  def maybe_update_if_changed(%{tenant: %{require_user: true}}, _exception) do
    :noop
  end

  def maybe_update_if_changed(%Supavisor.ClientHandler.Auth.Jit.Context{}, _exception) do
    :noop
  end

  def maybe_update_if_changed(context, %Supavisor.Errors.WrongPasswordError{}) do
    {user, db_user} = get_user_and_db_user(context)

    if Supavisor.CacheRefreshLimiter.cache_refresh_limited?(context.id) do
      Logger.debug("ClientHandler: Cache refresh rate-limited, skipping secret check")
      :noop
    else
      case fetch_secrets_from_database(context.id, context.tenant, user, db_user) do
        {:ok, new_secrets} ->
          case Supavisor.SecretCache.get_validation_secrets(
                 context.tenant.external_id,
                 db_user
               ) do
            {:ok, current_secrets} ->
              if sasl_secrets_changed?(current_secrets, new_secrets) do
                Logger.warning("ClientHandler: Validation secrets changed, updating cache")

                Supavisor.SecretCache.put_validation_secrets(
                  context.tenant.external_id,
                  db_user,
                  new_secrets
                )

                :changed
              else
                :noop
              end

            {:error, :not_found} ->
              # No cached secrets — store the fresh ones
              Supavisor.SecretCache.put_validation_secrets(
                context.tenant.external_id,
                db_user,
                new_secrets
              )

              :changed
          end

        {:error, reason} ->
          Logger.error("ClientHandler: Auth secrets check error: #{inspect(reason)}")
          :noop
      end
    end
  end

  def maybe_update_if_changed(_context, _exception) do
    :noop
  end

  # Derives SCRAM-SHA-256 secrets from a plaintext password.
  #
  # Generates a random salt and computes the SCRAM key material. Can be used
  # to perform SCRAM authentication for users that don't have an auth_query
  # enabled, but instead have `require_user: true`.
  @spec sasl_secrets_from_password(String.t(), String.t()) :: SASLSecrets.t()
  defp sasl_secrets_from_password(user, password) do
    iterations = 4096
    salt = :crypto.strong_rand_bytes(16)
    salted_password = :pgo_scram.hi(:pgo_sasl_prep_profile.validate([password]), salt, iterations)
    client_key = :pgo_scram.hmac(salted_password, "Client Key")
    stored_key = :pgo_scram.h(client_key)
    server_key = :pgo_scram.hmac(salted_password, "Server Key")

    %SASLSecrets{
      user: user,
      digest: "SCRAM-SHA-256",
      iterations: iterations,
      salt: Base.encode64(salt),
      stored_key: stored_key,
      server_key: server_key,
      client_key: client_key
    }
  end

  defp fetch_secrets_from_database(id, tenant, user, db_user) do
    with :ok <- Supavisor.CircuitBreaker.check(tenant.external_id, :get_secrets),
         {:ok, secrets} <- fetch_from_secret_checker_or_auth_query(id, tenant, user, db_user) do
      {:ok, secrets}
    else
      {:error, %Supavisor.Errors.CircuitBreakerError{}} = error ->
        error

      {:error, _} = error ->
        Supavisor.CircuitBreaker.record_failure(tenant.external_id, :get_secrets)
        error
    end
  end

  defp fetch_from_secret_checker_or_auth_query(id, tenant, user, db_user) do
    case Supavisor.SecretChecker.get_secrets(id) do
      {:ok, _} = ok ->
        ok

      {:error, :not_started} ->
        Logger.info("SecretChecker not started, using a one-off auth_query connection")
        manager = %ManagerSecrets{db_user: user.db_user, db_password: user.db_password}
        {:ok, conn} = AuthQuery.start_link(tenant, manager)

        case AuthQuery.fetch_user_secret(conn, tenant.auth_query, db_user) do
          {:ok, sasl_secrets} ->
            AuthQuery.stop_connection_async(conn)
            {:ok, from_sasl_secrets(sasl_secrets)}

          {:error, _} = error ->
            AuthQuery.stop_connection_async(conn)
            error
        end

      {:error, _} = error ->
        error
    end
  end

  defp get_user_and_db_user(%SCRAM.Context{} = ctx),
    do: SCRAM.get_user_and_db_user(ctx)

  defp get_user_and_db_user(%Password.Context{} = ctx),
    do: Password.get_user_and_db_user(ctx)

  # Notice that this is only valid for pg_shadow sourced SASL secrets, since the salt will change
  # if we have locally generated password.
  defp sasl_secrets_changed?(%__MODULE__{sasl_secrets: current}, %__MODULE__{sasl_secrets: new}) do
    %{current | client_key: nil} != %{new | client_key: nil}
  end
end
