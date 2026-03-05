defmodule Supavisor.ClientHandler.Proxy do
  @moduledoc """
  Handles proxy connection logic for ClientHandler.
  """

  require Logger

  alias Supavisor.ClientHandler.Proxy.Supervisor, as: ProxySupervisor

  @registry Supavisor.Registry.Tenants
  @max_sup_retries 3

  @type start_error ::
          :max_proxy_connections_reached
          | :failed_to_start_proxy_connection
          | :proxy_supervisor_unavailable

  @type auth_overrides :: %{
          port: :inet.port_number(),
          host: charlist(),
          ip_version: :inet | :inet6,
          upstream_ssl: boolean(),
          upstream_tls_ca: String.t() | nil,
          upstream_verify: String.t() | nil
        }

  @doc """
  Starts a proxy DbHandler for the given tenant.

  Ensures the proxy supervisor tree exists, then starts a DbHandler under it.

  Retries up to #{@max_sup_retries} times when the supervisor disappears between
  lookup and use (race with watchdog shutdown).

  Returns `{:ok, db_pid}` on success, or one of:
  - `{:error, :max_proxy_connections_reached}` if the connection limit has been reached
  - `{:error, :failed_to_start_proxy_connection}` if the child process failed to start
  - `{:error, :proxy_supervisor_unavailable}` if the supervisor could not be started after retries
  """
  @spec start_proxy_connection(Supavisor.id(), pos_integer(), map(), map()) ::
          {:ok, pid()} | {:error, start_error()}
  def start_proxy_connection(id, max_clients, auth, tenant_feature_flags) do
    child_spec = {Supavisor.DbHandler, build_db_handler_args(id, auth, tenant_feature_flags)}
    do_start_proxy_connection(id, max_clients, child_spec, @max_sup_retries)
  end

  # This function is public for test purposes, so we can test the logic
  # with mock processes, not DbHandlers
  @doc false
  def do_start_proxy_connection(_id, _max_clients, _child_spec, 0) do
    {:error, :proxy_supervisor_unavailable}
  end

  def do_start_proxy_connection(id, max_clients, child_spec, retries) do
    try do
      with :ok <- ensure_proxy_sup(id, max_clients),
           {:ok, pid} <- ProxySupervisor.start_connection(id, child_spec) do
        {:ok, pid}
      else
        {:error, :max_children} ->
          {:error, :max_proxy_connections_reached}

        {:error, :proxy_sup_not_found} ->
          do_start_proxy_connection(id, max_clients, child_spec, retries - 1)

        {:error, :failed_to_start} ->
          {:error, :failed_to_start_proxy_connection}
      end
    catch
      :exit, _reason ->
        do_start_proxy_connection(id, max_clients, child_spec, retries - 1)
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
    end
  end

  @spec prepare_proxy_connection(Supavisor.id()) ::
          {:ok, auth_overrides()} | {:error, term()}
  def prepare_proxy_connection(id) do
    case Supavisor.get_pool_ranch(id) do
      {:ok, %{port: port, host: host}} ->
        {:ok,
         %{
           port: port,
           host: to_charlist(host),
           ip_version: :inet,
           upstream_ssl: false,
           upstream_tls_ca: nil,
           upstream_verify: nil
         }}

      error ->
        {:error, error}
    end
  end

  @spec build_db_handler_args(Supavisor.id(), map(), map()) :: map()
  defp build_db_handler_args(id, auth, tenant_feature_flags) do
    {tenant, user, _mode, _db_name, _search_path} = id

    %{
      id: id,
      auth: auth,
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
