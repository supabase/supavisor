defmodule Supavisor.SecretCacheTest do
  use ExUnit.Case, async: false

  alias Supavisor.SecretCache
  alias Supavisor.TenantCache

  setup do
    Cachex.clear(Supavisor.Cache)
    :ok
  end

  defp setup_tenant_cache(id) do
    table = :ets.new(:tenant_cache, [:set, :public])
    Registry.register(Supavisor.Registry.Tenants, {:cache, id}, table)
    table
  end

  test "bypass users skip validation cache but keep upstream cache" do
    tenant = "test_tenant"
    user = "bypass_user"
    id = {{:single, tenant}, user, :transaction, "postgres", nil}
    method = :auth_query
    secrets_fn = fn -> %{password: "secret123", client_key: "key123"} end

    setup_tenant_cache(id)

    SecretCache.put_validation_secrets(tenant, user, method, secrets_fn)
    SecretCache.put_upstream_auth_secrets(id, method, secrets_fn)

    # Validation secrets not cached for bypass users
    assert {:error, :not_found} = SecretCache.get_validation_secrets(tenant, user)

    # Upstream secrets still cached
    assert {:ok, {^method, _}} = SecretCache.get_upstream_auth_secrets(id)
  end

  test "normal users cache both types of secrets" do
    tenant = "test_tenant"
    user = "normal_user"
    id = {{:single, tenant}, user, :transaction, "postgres", nil}
    method = :auth_query
    secrets_fn = fn -> %{password: "secret123", client_key: "key123"} end

    setup_tenant_cache(id)

    SecretCache.put_validation_secrets(tenant, user, method, secrets_fn)
    SecretCache.put_upstream_auth_secrets(id, method, secrets_fn)

    assert {:ok, {^method, _}} = SecretCache.get_validation_secrets(tenant, user)
    assert {:ok, {^method, _}} = SecretCache.get_upstream_auth_secrets(id)
  end

  test "put_validation_secrets skips caching for bypass users" do
    tenant = "test_tenant"
    user = "temp_user"
    method = :auth_query
    secrets_fn = fn -> %{password: "secret123"} end

    SecretCache.put_validation_secrets(tenant, user, method, secrets_fn)

    assert {:error, :not_found} = SecretCache.get_validation_secrets(tenant, user)
  end

  test "fetch_validation_secrets calls fetch_fn every time for bypass users" do
    tenant = "test_tenant"
    user = "bypass_user"
    method = :auth_query
    test_pid = self()

    fetch_fn = fn ->
      send(test_pid, :fetch_called)
      {:ok, {method, fn -> %{password: "secret123"} end}}
    end

    # First call
    assert {:ok, {^method, _}} = SecretCache.fetch_validation_secrets(tenant, user, fetch_fn)
    assert_receive :fetch_called

    # Second call should call fetch_fn again (no caching)
    assert {:ok, {^method, _}} = SecretCache.fetch_validation_secrets(tenant, user, fetch_fn)
    assert_receive :fetch_called
  end

  test "fetch_validation_secrets caches for normal users" do
    tenant = "test_tenant"
    user = "normal_user"
    method = :auth_query
    test_pid = self()

    fetch_fn = fn ->
      send(test_pid, :fetch_called)
      {:ok, {method, fn -> %{password: "secret123"} end}}
    end

    # First call
    assert {:ok, {^method, _}} = SecretCache.fetch_validation_secrets(tenant, user, fetch_fn)
    assert_receive :fetch_called

    # Second call should use cache (fetch_fn not called again)
    assert {:ok, {^method, _}} = SecretCache.fetch_validation_secrets(tenant, user, fetch_fn)
    refute_receive :fetch_called
  end

  test "upstream secrets stored in tenant cache are accessible" do
    tenant = "test_tenant"
    user = "normal_user"
    id = {{:single, tenant}, user, :transaction, "postgres", nil}
    method = :password
    secrets_fn = fn -> %{password: "secret123", client_key: "key123"} end

    setup_tenant_cache(id)

    SecretCache.put_upstream_auth_secrets(id, method, secrets_fn)

    # Should be able to retrieve from tenant cache
    assert {:ok, {^method, ^secrets_fn}} = SecretCache.get_upstream_auth_secrets(id)

    # Verify it's actually in the ETS table
    assert {:ok, {^method, ^secrets_fn}} = TenantCache.get_upstream_auth_secrets(id)
  end

  test "upstream secrets not found returns error" do
    tenant = "test_tenant"
    user = "normal_user"
    id = {{:single, tenant}, user, :transaction, "postgres", nil}

    # No tenant cache registered
    assert {:error, :not_found} = SecretCache.get_upstream_auth_secrets(id)
  end

  test "delete_upstream_auth_secrets removes secrets from tenant cache" do
    tenant = "test_tenant"
    user = "normal_user"
    id = {{:single, tenant}, user, :transaction, "postgres", nil}
    method = :password
    secrets_fn = fn -> %{password: "secret123", client_key: "key123"} end

    setup_tenant_cache(id)

    # Store secrets
    SecretCache.put_upstream_auth_secrets(id, method, secrets_fn)
    assert {:ok, {^method, ^secrets_fn}} = SecretCache.get_upstream_auth_secrets(id)

    # Delete secrets via SecretCache
    SecretCache.delete_upstream_auth_secrets(id)

    # Verify secrets are gone
    assert {:error, :not_found} = SecretCache.get_upstream_auth_secrets(id)
    assert {:error, :not_found} = TenantCache.get_upstream_auth_secrets(id)
  end

  test "delete_upstream_auth_secrets is idempotent" do
    tenant = "test_tenant"
    user = "normal_user"
    id = {{:single, tenant}, user, :transaction, "postgres", nil}

    setup_tenant_cache(id)

    # Delete when nothing exists should not crash
    assert true = SecretCache.delete_upstream_auth_secrets(id)
    assert true = SecretCache.delete_upstream_auth_secrets(id)
  end
end
