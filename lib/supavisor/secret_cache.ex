defmodule Supavisor.SecretCache do
  @moduledoc """
  Manages caching of authentication secrets for database users.

  Two types of secrets are cached with different purposes:

  1. Validation secrets: used by ClientHandler to validate incoming client authentication
  2. Upstream secrets: used by DbHandler to authenticate TO the upstream database
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
  Caches validation secrets
  """
  def put_validation_secrets(tenant, user, method, secrets_fn) do
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
  Invalidates all cached secrets for a tenant/user across the cluster.
  """
  def invalidate(tenant, user) do
    :erpc.multicast([node() | Node.list()], fn ->
      Cachex.del(Supavisor.Cache, {:secrets_for_validation, tenant, user})
      Cachex.del(Supavisor.Cache, {:secrets_for_upstream_auth, tenant, user})
      Cachex.del(Supavisor.Cache, {:secrets_check, tenant, user})
    end)
  end
end
