defmodule Supavisor.SecretCache do
  @moduledoc """
  Manages caching of authentication secrets for database users.

  Two types of secrets are cached with different purposes:

  1. Validation secrets: used by ClientHandler to validate incoming client authentication
  2. Upstream secrets: used by DbHandler to authenticate TO the upstream database

  ## Cache Bypass

  Certain users can be configured to bypass validation secret caching via the
  `CACHE_BYPASS_USERS` environment variable (comma-separated list of usernames).

  For bypass users:
  - Validation secrets are never cached (always fetched fresh from the database)
  - Upstream auth secrets are still cached (required for database connections)
  - Useful for users with temporary passwords or frequently changing credentials
  """

  require Logger

  @default_secrets_ttl :timer.hours(24)

  @doc """
  Gets validation secrets for validating incoming client authentication requests.
  """
  def get_validation_secrets(tenant, user) do
    case Cachex.get(Supavisor.Cache, {:secrets_for_validation, tenant, user}) do
      {:ok, {:cached, secrets}} ->
        {:ok, secrets}

      _other ->
        {:error, :not_found}
    end
  end

  @doc """
  Fetches validation secrets with cache support and fallback function.

  Uses Cachex.fetch which provides mutex guarantees to avoid multiple concurrent
  fetches. For bypass users, always calls the fetch function directly.
  """
  def fetch_validation_secrets(tenant, user, fetch_fn) do
    if should_bypass_cache?(user) do
      fetch_fn.()
    else
      cache_key = {:secrets_for_validation, tenant, user}

      cachex_fetch_fn = fn _key ->
        case fetch_fn.() do
          {:ok, secrets} ->
            put_validation_secrets(tenant, user, secrets)
            {:commit, {:cached, secrets}, ttl: @default_secrets_ttl}

          {:error, _} = resp ->
            {:ignore, resp}
        end
      end

      case Cachex.fetch(Supavisor.Cache, cache_key, cachex_fetch_fn) do
        {:ok, {:cached, value}} -> {:ok, value}
        {:commit, {:cached, value}, _opts} -> {:ok, value}
        {:ignore, resp} -> resp
        {:error, _} = error -> error
      end
    end
  end

  @doc """
  Gets auth secrets to authenticate to the upstream database.
  """
  def get_upstream_auth_secrets(id) do
    Supavisor.TenantCache.get_upstream_auth_secrets(id)
  end

  @doc """
  Caches validation secrets.

  For users in the cache bypass list, this function does nothing (no caching occurs).
  """
  def put_validation_secrets(
        tenant,
        user,
        %Supavisor.ClientHandler.Auth.ValidationSecrets{} = secrets
      ) do
    if should_bypass_cache?(user) do
      :ok
    else
      # Strip client_key from sasl_secrets before caching
      cleaned =
        if secrets.sasl_secrets do
          %{secrets | sasl_secrets: %{secrets.sasl_secrets | client_key: nil}}
        else
          secrets
        end

      validation_key = {:secrets_for_validation, tenant, user}

      Cachex.put(Supavisor.Cache, validation_key, {:cached, cleaned}, ttl: @default_secrets_ttl)
    end
  end

  @doc """
  Caches upstream auth secrets in the tenant-specific cache.
  """
  def put_upstream_auth_secrets(id, secrets) do
    Supavisor.TenantCache.put_upstream_auth_secrets(id, secrets)
  end

  @doc """
  Caches validation secrets only if missing.
  """
  def put_validation_secrets_if_missing(tenant, user, secrets) do
    validation_key = {:secrets_for_validation, tenant, user}

    case Cachex.get(Supavisor.Cache, validation_key) do
      {:ok, {:cached, _value}} ->
        :ok

      _other ->
        put_validation_secrets(tenant, user, secrets)
    end
  end

  @doc """
  Invalidates all cached secrets for a tenant/user across the cluster.
  """
  def invalidate(tenant, user) do
    :erpc.multicast([node() | Node.list()], fn ->
      Cachex.del(Supavisor.Cache, {:secrets_for_validation, tenant, user})
      Cachex.del(Supavisor.Cache, {:secrets_check, tenant, user})
    end)
  end

  @doc """
  Deletes upstream auth secrets from the tenant cache.
  """
  def delete_upstream_auth_secrets(id) do
    Supavisor.TenantCache.delete_upstream_auth_secrets(id)
  end

  @doc false
  defp should_bypass_cache?(user) do
    bypass_users = Application.get_env(:supavisor, :cache_bypass_users, [])
    user in bypass_users
  end
end
