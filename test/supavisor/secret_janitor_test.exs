defmodule Supavisor.SecretJanitorTest do
  use ExUnit.Case, async: false

  alias Supavisor.SecretCache
  alias Supavisor.SecretJanitor

  defmodule MockManager do
    use GenServer

    def start_link(opts) do
      id = Keyword.fetch!(opts, :id)
      name = {:via, Registry, {Supavisor.Registry.Tenants, {:manager, id}}}
      GenServer.start_link(__MODULE__, opts, name: name)
    end

    def init(opts), do: {:ok, opts}
  end

  setup do
    Cachex.clear(Supavisor.Cache)
    :ok
  end

  test "cleans orphaned secrets but preserves active pool secrets" do
    method = :password
    secrets_fn = fn -> %{password: "secret123"} end

    orphaned_tenant = "orphaned_tenant"
    orphaned_user = "orphaned_user"
    active_tenant = "active_tenant"
    active_user = "active_user"

    active_id = {{:single, active_tenant}, active_user, :transaction, "postgres", nil}
    {:ok, _pid} = start_supervised({MockManager, id: active_id})

    SecretCache.put_upstream_auth_secrets(
      orphaned_tenant,
      orphaned_user,
      method,
      secrets_fn,
      :infinity
    )

    SecretCache.put_upstream_auth_secrets(
      active_tenant,
      active_user,
      method,
      secrets_fn,
      :infinity
    )

    SecretJanitor.cleanup_orphaned_secrets()

    assert {:error, :not_found} =
             SecretCache.get_upstream_auth_secrets(orphaned_tenant, orphaned_user)

    assert {:ok, {^method, _}} = SecretCache.get_upstream_auth_secrets(active_tenant, active_user)
  end

  test "does not clean proxy mode secrets with finite TTL" do
    method = :password
    secrets_fn = fn -> %{password: "secret123"} end

    proxy_tenant = "proxy_tenant"
    proxy_user = "proxy_user"

    SecretCache.put_upstream_auth_secrets(
      proxy_tenant,
      proxy_user,
      method,
      secrets_fn,
      :timer.hours(24)
    )

    SecretJanitor.cleanup_orphaned_secrets()

    assert {:ok, {^method, _}} = SecretCache.get_upstream_auth_secrets(proxy_tenant, proxy_user)
  end
end
