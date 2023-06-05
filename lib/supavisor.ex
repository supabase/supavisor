defmodule Supavisor do
  @moduledoc false
  require Logger
  alias Supavisor.{Tenants, Tenants.Tenant, Manager}

  @registry Supavisor.Registry.Tenants
  @type workers :: %{manager: pid, pool: pid}

  @spec start(String.t(), String.t()) :: {:ok, pid} | {:error, any()}
  def start(tenant, user_alias) do
    case get_global_sup(tenant, user_alias) do
      nil ->
        start_local_pool(tenant, user_alias)

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
      Process.monitor(workers.manager)
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

  @spec start_local_pool(String.t(), String.t()) :: {:ok, pid} | {:error, any()}
  defp start_local_pool(tenant, user_alias) do
    Logger.debug("Starting pool for #{inspect({tenant, user_alias})}")

    case Tenants.get_pool_config(tenant, user_alias) do
      %Tenant{} = tenant_record ->
        %{
          db_host: db_host,
          db_port: db_port,
          db_database: db_database,
          default_parameter_status: ps,
          users: [
            %{
              db_user: db_user,
              db_password: db_pass,
              pool_size: pool_size,
              mode_type: mode
            }
          ]
        } = tenant_record

        auth = %{
          host: String.to_charlist(db_host),
          port: db_port,
          user: db_user,
          database: db_database,
          password: fn -> db_pass end,
          application_name: "supavisor"
        }

        args = %{
          tenant: tenant,
          user_alias: user_alias,
          auth: auth,
          pool_size: pool_size,
          mode: mode,
          default_parameter_status: ps
        }

        DynamicSupervisor.start_child(
          {:via, PartitionSupervisor, {Supavisor.DynamicSupervisor, {tenant, user_alias}}},
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

  @spec set_parameter_status(String.t(), String.t(), [{binary, binary}]) ::
          :ok | {:error, :not_found}
  def set_parameter_status(tenant, user_alias, ps) do
    case get_local_manager(tenant, user_alias) do
      nil -> {:error, :not_found}
      pid -> Manager.set_parameter_status(pid, ps)
    end
  end
end
