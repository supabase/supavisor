defmodule Supavisor.ClientHandler.Proxy do
  @moduledoc """
  Handles proxy connection logic for ClientHandler.

  This module prepares proxy connections and database handler arguments
  while leaving socket operations and process management to ClientHandler.
  """

  require Logger

  @registry Supavisor.Registry.Tenants

  @doc """
  Gets or starts a proxy poolboy pool for the given tenant id.

  The pool uses DbHandler as worker module with `proxy_pool: true` init.
  Workers start idle and receive connection details via `DbHandler.configure/2`.
  """
  @spec get_or_start_proxy_pool(Supavisor.id(), pos_integer()) ::
          {:ok, pid()} | {:error, term()}
  def get_or_start_proxy_pool(id, max_clients) do
    key = {:proxy_pool, id}

    case Registry.lookup(@registry, key) do
      [{pid, _}] ->
        {:ok, pid}

      [] ->
        start_proxy_pool(key, id, max_clients)
    end
  end

  defp start_proxy_pool(key, id, max_clients) do
    pool_config = [
      name: {:via, Registry, {@registry, key}},
      worker_module: Supavisor.DbHandler,
      size: 0,
      max_overflow: max_clients,
      strategy: :lifo
    ]

    case DynamicSupervisor.start_child(
           {:via, PartitionSupervisor, {Supavisor.DynamicSupervisor, id}},
           %{
             id: key,
             start: {:poolboy, :start_link, [pool_config, %{proxy_pool: true}]},
             restart: :temporary,
             type: :supervisor
           }
         ) do
      {:ok, _} ->
        lookup_pool(key)

      {:error, {:shutdown, {:failed_to_start_child, _, {:already_started, _}}}} ->
        lookup_pool(key)

      error ->
        error
    end
  end

  defp lookup_pool(key) do
    [{pool_pid, _}] = Registry.lookup(@registry, key)
    {:ok, pool_pid}
  end

  @doc """
  Attempts a non-blocking checkout from the proxy pool.

  Returns `{:ok, db_pid}` if a slot is available, or
  `{:error, :max_proxy_connections_reached}` if the pool is full.
  """
  @spec checkout_proxy_pool(pid()) :: {:ok, pid()} | {:error, :max_proxy_connections_reached}
  def checkout_proxy_pool(pool) do
    case :poolboy.checkout(pool, false) do
      :full -> {:error, :max_proxy_connections_reached}
      pid when is_pid(pid) -> {:ok, pid}
    end
  end

  @spec prepare_proxy_connection(map()) ::
          {:ok, map()} | {:error, term()}
  def prepare_proxy_connection(data) do
    case Supavisor.get_pool_ranch(data.id) do
      {:ok, %{port: port, host: host}} ->
        updated_auth =
          Map.merge(data.auth, %{
            port: port,
            host: to_charlist(host),
            ip_version: :inet,
            upstream_ssl: false,
            upstream_tls_ca: nil,
            upstream_verify: nil
          })

        {:ok, %{data | auth: updated_auth}}

      error ->
        {:error, error}
    end
  end

  @spec build_db_handler_args(map()) :: map()
  def build_db_handler_args(data) do
    %{
      id: data.id,
      auth: data.auth,
      user: data.user,
      tenant: {:single, data.tenant},
      tenant_feature_flags: data.tenant_feature_flags,
      replica_type: :write,
      mode: :proxy,
      proxy: true,
      log_level: nil
    }
  end
end
