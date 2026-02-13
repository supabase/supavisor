defmodule Supavisor.ClientHandler.Proxy do
  @moduledoc """
  Handles proxy connection logic for ClientHandler.

  This module prepares proxy connections and database handler arguments
  while leaving socket operations and process management to ClientHandler.
  """

  @spec prepare_proxy_connection(map()) ::
          {:ok, map()} | {:error, Supavisor.Errors.PoolRanchNotFoundError.t()}
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

      {:error, _} = error ->
        error
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
