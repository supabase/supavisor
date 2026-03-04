defmodule Supavisor.ClientHandler.Proxy do
  @moduledoc """
  Handles proxy connection logic for ClientHandler.

  This module prepares proxy connections and database handler arguments
  while leaving socket operations and process management to ClientHandler.
  """

  require Logger

  alias Supavisor.ClientHandler.ProxySupervisor

  @registry Supavisor.Registry.Tenants

  @doc """
  Starts a proxy DbHandler for the given tenant.

  Ensures the proxy supervisor tree exists, then starts a DbHandler under it.
  Returns `{:ok, db_pid}` if a slot is available, or
  `{:error, :max_proxy_connections_reached}` if the connection limit has been reached.
  """
  @spec start_proxy_connection(Supavisor.id(), pos_integer(), map()) ::
          {:ok, pid()} | {:error, :max_proxy_connections_reached | term()}
  def start_proxy_connection(id, max_clients, args) do
    with :ok <- ensure_proxy_sup(id, max_clients) do
      case ProxySupervisor.start_connection(id, {Supavisor.DbHandler, args}) do
        {:ok, pid} -> {:ok, pid}
        {:error, :max_children} -> {:error, :max_proxy_connections_reached}
        error -> error
      end
    end
  end

  defp ensure_proxy_sup(id, max_clients) do
    case Registry.lookup(@registry, {:proxy_dyn_sup, id}) do
      [{_, _}] ->
        :ok

      [] ->
        start_proxy_sup(id, max_clients)
    end
  end

  defp start_proxy_sup(id, max_clients) do
    case DynamicSupervisor.start_child(
           {:via, PartitionSupervisor, {Supavisor.DynamicSupervisor, id}},
           %{
             id: {:proxy_sup, id},
             start: {ProxySupervisor, :start_link, [[id: id, max_clients: max_clients]]},
             restart: :temporary,
             type: :supervisor
           }
         ) do
      {:ok, _} ->
        :ok

      {:error, {:shutdown, {:failed_to_start_child, _, {:already_started, _}}}} ->
        :ok

      error ->
        error
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
