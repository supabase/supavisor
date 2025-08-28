defmodule Supavisor.Support.Tenants do
  @moduledoc """
  Integration test helpers for managing Supavisor tenants.

  This module provides utility functions for creating, terminating, and connecting to tenants
  in integration tests.
  """

  import Phoenix.ConnTest

  alias SupavisorWeb.Router.Helpers, as: Routes

  @endpoint SupavisorWeb.Endpoint

  @postgres_port 7432
  @postgres_user "postgres"
  @postgres_password "postgres"
  @postgres_db "postgres"
  @tenant_name "switching_test_tenant"
  @db_host "localhost"

  def create_tenant(conn, opts) do
    external_id = opts[:external_id] || @tenant_name

    tenant_attrs = %{
      db_host: opts[:hostname] || @db_host,
      db_port: opts[:port] || @postgres_port,
      db_database: opts[:database] || @postgres_db,
      external_id: external_id,
      ip_version: "auto",
      enforce_ssl: false,
      require_user: false,
      auth_query: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1;",
      users: [
        %{
          db_user: opts[:username] || @postgres_user,
          db_password: opts[:password] || @postgres_password,
          pool_size: 20,
          mode_type: "transaction",
          is_manager: true
        }
      ]
    }

    conn = put(conn, Routes.tenant_path(conn, :update, external_id), tenant: tenant_attrs)

    case conn.status do
      status when status in 200..201 ->
        :ok

      _status ->
        :ok
    end
  end

  def terminate_tenant(conn, external_id) do
    _conn = get(conn, Routes.tenant_path(conn, :terminate, external_id))
    :ok
  end

  def connection_opts(opts) do
    proxy_port = Application.fetch_env!(:supavisor, :proxy_port_transaction)
    external_id = opts[:external_id] || @tenant_name

    [
      hostname: opts[:hostname] || @db_host,
      port: proxy_port,
      database: opts[:database] || @postgres_db,
      username: "#{opts[:username] || @postgres_user}.#{external_id}",
      password: opts[:password] || @postgres_password,
      # This is important as otherwise Postgrex may try to reconnect in case of errors.
      # We want to avoid that, as it hides connection errors.
      backoff: nil
    ]
  end
end
