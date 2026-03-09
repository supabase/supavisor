defmodule Supavisor.ClientHandler.Proxy do
  @moduledoc """
  Handles proxy connection logic for ClientHandler.
  """

  require Logger
  require Supavisor

  alias Supavisor.ClientHandler.Proxy.Supervisor, as: ProxySupervisor

  alias Supavisor.Errors.{
    MaxConnectionsError,
    FailedToStartProxyConnectionError,
    ProxySupervisorUnavailableError
  }

  @max_sup_retries 3

  @type start_error ::
          MaxConnectionsError.t()
          | FailedToStartProxyConnectionError.t()
          | ProxySupervisorUnavailableError.t()

  @doc """
  Starts a proxy DbHandler for the given tenant.

  Ensures the proxy supervisor tree exists, then starts a DbHandler under it.

  Retries up to #{@max_sup_retries} times when the supervisor disappears between
  lookup and use (race with watchdog shutdown).

  Returns `{:ok, db_pid}` on success, or one of the errors defined in `start_error()`.
  """
  @spec start_proxy_connection(Supavisor.id(), pos_integer(), map(), map(), map()) ::
          {:ok, pid()} | {:error, start_error()}
  def start_proxy_connection(id, max_clients, auth, tenant_feature_flags, pool_ranch) do
    child_spec =
      Supavisor.DbHandler.child_spec(
        build_db_handler_args(id, auth, tenant_feature_flags, pool_ranch)
      )

    do_start_proxy_connection(id, max_clients, child_spec, @max_sup_retries)
  end

  # This function is public for test purposes, so we can test the logic
  # with mock processes, not DbHandlers
  @doc false
  @spec do_start_proxy_connection(
          Supavisor.id(),
          max_clients :: pos_integer(),
          Supervisor.child_spec(),
          attempts_remaining :: non_neg_integer()
        ) ::
          {:ok, pid()} | {:error, start_error()}
  def do_start_proxy_connection(_id, _max_clients, _child_spec, 0) do
    {:error, %ProxySupervisorUnavailableError{}}
  end

  def do_start_proxy_connection(id, max_clients, child_spec, retries) do
    with :ok <- ProxySupervisor.ensure_started(id, max_clients),
         {:ok, pid} <- ProxySupervisor.start_connection(id, child_spec) do
      {:ok, pid}
    else
      {:error, :max_children} ->
        {:error, MaxConnectionsError.new(:proxy, max_clients)}

      {:error, :proxy_sup_not_found} ->
        do_start_proxy_connection(id, max_clients, child_spec, retries - 1)

      {:error, :failed_to_start} ->
        {:error, %FailedToStartProxyConnectionError{}}
    end
  catch
    :exit, _reason ->
      do_start_proxy_connection(id, max_clients, child_spec, retries - 1)
  end

  @spec build_db_handler_args(Supavisor.id(), map(), map(), map()) :: map()
  defp build_db_handler_args(
         Supavisor.id(tenant: tenant, user: user) = id,
         auth,
         tenant_feature_flags,
         pool_ranch
       ) do
    proxy_auth =
      Map.merge(auth, %{
        port: pool_ranch.port,
        host: to_charlist(pool_ranch.host),
        ip_version: :inet,
        upstream_ssl: false,
        upstream_tls_ca: nil,
        upstream_verify: nil
      })

    %{
      id: id,
      auth: proxy_auth,
      user: user,
      tenant: tenant,
      tenant_feature_flags: tenant_feature_flags,
      replica_type: :write,
      mode: :proxy,
      proxy: true,
      log_level: nil
    }
  end
end
