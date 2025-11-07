defmodule Supavisor.SecretCacheTest do
  use ExUnit.Case, async: false

  alias Supavisor.SecretCache

  setup do
    Cachex.clear(Supavisor.Cache)
    :ok
  end

  test "bypass users skip validation cache but keep upstream cache" do
    tenant = "test_tenant"
    user = "bypass_user"
    method = :auth_query
    secrets_fn = fn -> %{password: "secret123", client_key: "key123"} end

    SecretCache.put_both(tenant, user, method, secrets_fn)

    # Validation secrets not cached
    assert {:error, :not_found} = SecretCache.get_validation_secrets(tenant, user)

    # Upstream secrets still cached
    assert {:ok, {^method, _}} = SecretCache.get_upstream_auth_secrets(tenant, user)
  end

  test "normal users cache both types of secrets" do
    tenant = "test_tenant"
    user = "normal_user"
    method = :auth_query
    secrets_fn = fn -> %{password: "secret123", client_key: "key123"} end

    SecretCache.put_both(tenant, user, method, secrets_fn)

    assert {:ok, {^method, _}} = SecretCache.get_validation_secrets(tenant, user)
    assert {:ok, {^method, _}} = SecretCache.get_upstream_auth_secrets(tenant, user)
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
end
