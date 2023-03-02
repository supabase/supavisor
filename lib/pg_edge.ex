defmodule PgEdge do
  @moduledoc false
  require Logger
  alias PgEdge.{Tenants, Tenants.Tenant, Manager}

  @registry PgEdge.Registry.Tenants
  @type workers :: %{manager: pid, pool: pid}

  @spec start(String.t()) :: {:ok, pid} | {:error, any()}
  def start(tenant) do
    case get_global_sup(tenant) do
      nil ->
        start_local_pool(tenant)

      pid ->
        {:ok, pid}
    end
  end

  @spec stop(String.t()) :: :ok | {:error, :tenant_not_found}
  def stop(tenant) do
    case get_global_sup(tenant) do
      nil -> {:error, :tenant_not_found}
      pid -> Supervisor.stop(pid)
    end
  end

  @spec get_local_workers(String.t()) :: {:ok, workers} | {:error, :worker_not_found}
  def get_local_workers(tenant) do
    workers = %{
      manager: get_local_manager(tenant),
      pool: get_local_pool(tenant)
    }

    if Map.values(workers) |> Enum.member?(nil) do
      Logger.error("Could not get workers for tenant #{tenant}")
      {:error, :worker_not_found}
    else
      {:ok, workers}
    end
  end

  @spec subscribe_local(pid, String.t()) :: {:ok, workers} | {:error, any()}
  def subscribe_local(pid, tenant) do
    with {:ok, workers} <- get_local_workers(tenant),
         :ok <- Manager.subscribe(workers.manager, pid) do
      {:ok, workers}
    else
      error ->
        error
    end
  end

  @spec subscribe_global(atom(), pid(), String.t()) :: {:ok, workers} | {:error, any()}
  def subscribe_global(tenant_node, pid, tenant) do
    if node() == tenant_node do
      subscribe_local(pid, tenant)
    else
      try do
        # TODO: tests for different cases
        :erpc.call(tenant_node, __MODULE__, :subscribe_local, [pid, tenant], 15_000)
        |> case do
          {:EXIT, _} = badrpc -> {:error, {:badrpc, badrpc}}
          result -> result
        end
      catch
        kind, reason -> {:error, {:badrpc, {kind, reason}}}
      end
    end
  end

  @spec get_global_sup(binary) :: pid() | nil
  def get_global_sup(tenant) do
    case :syn.whereis_name({:tenants, tenant}) do
      :undefined -> nil
      pid -> pid
    end
  end

  @spec get_local_pool(String.t()) :: pid() | nil
  def get_local_pool(tenant) do
    case Registry.lookup(@registry, {:pool, tenant}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  @spec get_local_manager(String.t()) :: pid() | nil
  def get_local_manager(tenant) do
    case Registry.lookup(@registry, {:manager, tenant}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  ## Internal functions

  @spec start_local_pool(String.t()) :: {:ok, pid} | {:error, any()}
  defp start_local_pool(tenant) do
    Logger.debug("Starting pool for #{tenant}")

    case Tenants.get_tenant_by_external_id(tenant) do
      %Tenant{} = tenant_record ->
        %{
          db_host: db_host,
          db_port: db_port,
          db_user: db_user,
          db_database: db_database,
          db_password: db_pass,
          pool_size: pool_size
        } = tenant_record

        auth = %{
          host: String.to_charlist(db_host),
          port: db_port,
          user: db_user,
          database: db_database,
          password: fn -> db_pass end,
          application_name: "pg_edge"
        }

        args = %{tenant: tenant, auth: auth, pool_size: pool_size}

        DynamicSupervisor.start_child(
          {:via, PartitionSupervisor, {PgEdge.DynamicSupervisor, tenant}},
          {PgEdge.TenantSupervisor, args}
        )
        |> case do
          {:error, {:already_started, pid}} -> {:ok, pid}
          resp -> resp
        end

      _ ->
        Logger.error("Can't find tenant with external_id #{tenant}")
        {:error, :tenant_not_found}
    end
  end
end
