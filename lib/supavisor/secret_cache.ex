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
      {:ok, {:cached, {method, secrets_fn}}} ->
        {:ok, {method, secrets_fn}}

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
          {:ok, {method, secrets_fn} = secrets} ->
            put_validation_secrets(tenant, user, method, secrets_fn)
            {:commit, {:cached, secrets}, ttl: @default_secrets_ttl}

          {:error, _} = resp ->
            {:ignore, resp}
        end
      end

      case Cachex.fetch(Supavisor.Cache, cache_key, cachex_fetch_fn) do
        {:ok, {:cached, value}} -> {:ok, value}
        {:commit, {:cached, value}, _opts} -> {:ok, value}
        {:ignore, resp} -> resp
      end
    end
  end

  @doc """
  Gets auth secrets to authenticate to the upstream database.
  """
  def get_upstream_auth_secrets(tenant, user) do
    case Cachex.get(Supavisor.Cache, {:secrets_for_upstream_auth, tenant, user}) do
      {:ok, {:cached, {method, secrets_fn}}} ->
        {:ok, {method, secrets_fn}}

      _other ->
        {:error, :not_found}
    end
  end

  @doc """
  Caches validation secrets.

  For users in the cache bypass list, this function does nothing (no caching occurs).
  """
  def put_validation_secrets(tenant, user, method, secrets_fn) do
    if should_bypass_cache?(user) do
      :ok
    else
      secrets_map = secrets_fn.()

      validation_secrets_fn = fn ->
        Map.delete(secrets_map, :client_key)
      end

      validation_key = {:secrets_for_validation, tenant, user}
      validation_value = {method, validation_secrets_fn}

      Cachex.put(Supavisor.Cache, validation_key, {:cached, validation_value},
        ttl: @default_secrets_ttl
      )
    end
  end

  @doc """
  Caches upstream auth secrets
  """
  def put_upstream_auth_secrets(tenant, user, method, secrets_with_client_key_fn) do
    upstream_auth_key = {:secrets_for_upstream_auth, tenant, user}
    upstream_auth_value = {method, secrets_with_client_key_fn}

    Cachex.put(Supavisor.Cache, upstream_auth_key, {:cached, upstream_auth_value},
      ttl: @default_secrets_ttl
    )
  end

  @doc """
  Caches both validation and upstream auth secrets.

  Used when you have secrets with client_key and want to cache both versions.

  For users in the cache bypass list, only caches upstream auth secrets (validation
  secrets are skipped).
  """
  def put_both(tenant, user, method, secrets_with_client_key_fn) do
    put_validation_secrets(tenant, user, method, secrets_with_client_key_fn)
    put_upstream_auth_secrets(tenant, user, method, secrets_with_client_key_fn)
  end

  @doc """
  Caches validation secrets only if missing.
  """
  # TODO: is this really necessary?
  def put_validation_secrets_if_missing(tenant, user, method, secrets_fn) do
    validation_key = {:secrets_for_validation, tenant, user}

    case Cachex.get(Supavisor.Cache, validation_key) do
      {:ok, {:cached, _value}} ->
        :ok

      _other ->
        put_validation_secrets(tenant, user, method, secrets_fn)
    end
  end

  @doc """
  Short-term cache indicating that cached validation secrets were checked against
  the upstream database recently.
  """
  def put_check(tenant, user, method, secrets_fn) do
    key = {:secrets_check, tenant, user}
    value = {method, secrets_fn}
    Cachex.put(Supavisor.Cache, key, {:cached, value}, ttl: 5_000)
  end

  @doc """
  Clean upstream secrets
  """
  def clean_upstream_secrets(tenant, user) do
    Cachex.del(Supavisor.Cache, {:secrets_for_upstream_auth, tenant, user})
  end

  @doc """
  Invalidates all cached secrets for a tenant/user across the cluster.
  """
  def invalidate(tenant, user) do
    :erpc.multicast([node() | Node.list()], fn ->
      Cachex.del(Supavisor.Cache, {:secrets_for_validation, tenant, user})
      Cachex.del(Supavisor.Cache, {:secrets_for_upstream_auth, tenant, user})
      Cachex.del(Supavisor.Cache, {:secrets_check, tenant, user})
    end)
  end

  @doc false
  defp should_bypass_cache?(user) do
    bypass_users = Application.get_env(:supavisor, :cache_bypass_users, [])
    user in bypass_users
  end
end
