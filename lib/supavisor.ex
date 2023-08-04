defmodule Supavisor do
  @moduledoc false
  require Logger
  alias Supavisor.Helpers, as: H
  alias Supavisor.{Tenants, Tenants.Tenant, Manager}

  @registry Supavisor.Registry.Tenants
  @type workers :: %{manager: pid, pool: pid}

  @spec start(String.t(), String.t(), fun(), String.t(), atom() | nil) ::
          {:ok, pid} | {:error, any()}
  def start(tenant, user_alias, client_key, conn_user, def_mode_type \\ nil) do
    case get_global_sup(tenant, conn_user) do
      nil ->
        start_local_pool(tenant, user_alias, client_key, def_mode_type)

      pid ->
        {:ok, pid}
    end
  end

  @spec stop(String.t(), String.t()) :: :ok | {:error, :tenant_not_found}
  def stop(tenant, user_alias) do
    case get_global_sup(tenant, user_alias) do
      nil -> {:error, :tenant_not_found}
      pid -> Supervisor.stop(pid)
    end
  end

  @spec get_local_workers(String.t(), String.t()) :: {:ok, workers} | {:error, :worker_not_found}
  def get_local_workers(tenant, user_alias) do
    workers = %{
      manager: get_local_manager(tenant, user_alias),
      pool: get_local_pool(tenant, user_alias)
    }

    if Map.values(workers) |> Enum.member?(nil) do
      Logger.error("Could not get workers for tenant #{inspect({tenant, user_alias})}")
      {:error, :worker_not_found}
    else
      {:ok, workers}
    end
  end

  @spec subscribe_local(pid, String.t(), String.t()) :: {:ok, workers, iodata()} | {:error, any()}
  def subscribe_local(pid, tenant, user_alias) do
    with {:ok, workers} <- get_local_workers(tenant, user_alias),
         {:ok, ps} <- Manager.subscribe(workers.manager, pid) do
      {:ok, workers, ps}
    else
      error ->
        error
    end
  end

  @spec subscribe_global(atom(), pid(), String.t(), String.t()) ::
          {:ok, workers, iodata()} | {:error, any()}
  def subscribe_global(tenant_node, pid, tenant, user_alias) do
    if node() == tenant_node do
      subscribe_local(pid, tenant, user_alias)
    else
      try do
        # TODO: tests for different cases
        :erpc.call(tenant_node, __MODULE__, :subscribe_local, [pid, tenant, user_alias], 15_000)
        |> case do
          {:EXIT, _} = badrpc -> {:error, {:badrpc, badrpc}}
          result -> result
        end
      catch
        kind, reason -> {:error, {:badrpc, {kind, reason}}}
      end
    end
  end

  @spec get_global_sup(String.t(), String.t()) :: pid() | nil
  def get_global_sup(tenant, user_alias) do
    case :syn.whereis_name({:tenants, {tenant, user_alias}}) do
      :undefined -> nil
      pid -> pid
    end
  end

  @doc """
  During netsplits, or due to certain internal conflicts, :syn may store inconsistent data across the cluster.
  This function terminates all connection trees related to a specific tenant.
  """
  @spec dirty_terminate(String.t(), pos_integer()) :: map()
  def dirty_terminate(tenant, timeout \\ 15_000) do
    Registry.lookup(Supavisor.Registry.TenantSups, tenant)
    |> Enum.reduce(%{}, fn {pid, %{user: user}}, acc ->
      stop =
        try do
          Supervisor.stop(pid, :shutdown, timeout)
        catch
          error, reason -> {:error, {error, reason}}
        end

      resp = %{
        stop: stop,
        cache: del_all_cache(tenant, user)
      }

      Map.put(acc, user, resp)
    end)
  end

  @spec del_all_cache(String.t(), String.t()) :: map()
  def del_all_cache(tenant, user) do
    %{secrets: Cachex.del(Supavisor.Cache, {:secrets, tenant, user})}
  end

  @spec get_local_pool(String.t(), String.t()) :: pid() | nil
  def get_local_pool(tenant, user_alias) do
    case Registry.lookup(@registry, {:pool, {tenant, user_alias}}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  @spec get_local_manager(String.t(), String.t()) :: pid() | nil
  def get_local_manager(tenant, user_alias) do
    case Registry.lookup(@registry, {:manager, {tenant, user_alias}}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  ## Internal functions

  @spec start_local_pool(String.t(), String.t(), term(), atom() | nil) ::
          {:ok, pid} | {:error, any()}
  defp start_local_pool(tenant, user_alias, auth_secrets, def_mode_type) do
    {method, secrets} = auth_secrets
    Logger.debug("Starting pool for #{inspect({tenant, user_alias, method})}")

    case Tenants.get_pool_config(tenant, user_alias) do
      %Tenant{} = tenant_record ->
        %{
          db_host: db_host,
          db_port: db_port,
          db_database: db_database,
          default_parameter_status: ps,
          ip_version: ip_ver,
          default_pool_size: def_pool_size,
          default_max_clients: def_max_clients,
          users: [
            %{
              db_user: db_user,
              db_password: db_pass,
              pool_size: pool_size,
              mode_type: mode_type,
              max_clients: max_clients
            }
          ]
        } = tenant_record

        {id, mode, pool_size, max_clients} =
          if method == :auth_query do
            {{tenant, secrets.().user}, def_mode_type, def_pool_size, def_max_clients}
          else
            {{tenant, user_alias}, mode_type, pool_size, max_clients}
          end

        auth = %{
          host: String.to_charlist(db_host),
          port: db_port,
          user: db_user,
          database: db_database,
          password: fn -> db_pass end,
          application_name: "supavisor",
          ip_version: H.ip_version(ip_ver, db_host),
          upstream_ssl: tenant_record.upstream_ssl,
          upstream_verify: tenant_record.upstream_verify,
          upstream_tls_ca: H.upstream_cert(tenant_record.upstream_tls_ca),
          require_user: tenant_record.require_user,
          secrets: secrets
        }

        args = %{
          id: id,
          tenant: tenant,
          user_alias: user_alias,
          auth: auth,
          pool_size: pool_size,
          mode: mode,
          default_parameter_status: ps,
          max_clients: max_clients
        }

        DynamicSupervisor.start_child(
          {:via, PartitionSupervisor, {Supavisor.DynamicSupervisor, id}},
          {Supavisor.TenantSupervisor, args}
        )
        |> case do
          {:error, {:already_started, pid}} -> {:ok, pid}
          resp -> resp
        end

      _ ->
        Logger.error("Can't find tenant with external_id #{inspect({tenant, user_alias})}")

        {:error, :tenant_not_found}
    end
  end

  @spec set_parameter_status({String.t(), String.t()}, [{binary, binary}]) ::
          :ok | {:error, :not_found}
  def set_parameter_status({tenant, user}, ps) do
    case get_local_manager(tenant, user) do
      nil -> {:error, :not_found}
      pid -> Manager.set_parameter_status(pid, ps)
    end
  end
end
