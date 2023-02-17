defmodule PgEdge do
  @moduledoc false
  require Logger
  alias PgEdge.{Tenants, Tenants.Tenant, Manager}

  @type workers :: %{manager: pid, pool: pid}

  @spec start(String.t()) :: {:ok, pid} | {:error, any()}
  def start(tenant) do
    get_sup_pid(tenant)
    |> case do
      :undefined ->
        Semaphore.call_linksafe(tenant, 1, fn ->
          start_pool(tenant)
        end)
        |> case do
          {:error, :max} -> {:error, :locked}
          resp -> resp
        end

      pid ->
        {:ok, pid}
    end
  end

  @spec stop(String.t()) :: :ok | {:error, :tenant_not_found}
  def stop(tenant) do
    case get_sup_pid(tenant) do
      :undefined -> {:error, :tenant_not_found}
      pid -> Supervisor.stop(pid)
    end
  end

  @spec get_workers(String.t()) :: {:ok, workers} | {:error, :worker_not_found}
  def get_workers(tenant) do
    workers = %{
      manager: get_manager_pid(tenant),
      pool: get_pool_pid(tenant)
    }

    if Map.values(workers) |> Enum.member?(:undefined) do
      Logger.error("Could not get workers for tenant #{tenant}")
      {:error, :worker_not_found}
    else
      {:ok, workers}
    end
  end

  @spec subscribe(pid, String.t()) :: {:ok, workers} | {:error, any()}
  def subscribe(pid, tenant) do
    with {:ok, workers} <- get_workers(tenant),
         :ok <- Manager.subscribe(workers.manager, pid) do
      {:ok, workers}
    else
      error ->
        error
    end
  end

  @spec subscribe_dist(atom(), pid(), String.t()) :: {:ok, workers} | {:error, any()}
  def subscribe_dist(tenant_node, pid, tenant) do
    if node() == tenant_node do
      subscribe(pid, tenant)
    else
      :rpc.call(tenant_node, __MODULE__, :subscribe, [pid, tenant], 15_000)
      |> case do
        {:badrpc, _} = reason -> {:error, reason}
        response -> response
      end
    end
  end

  def supervisor_name(tenant) do
    {:tenants, tenant}
  end

  def pool_name(external_id) do
    {PgEdge.Registry.Tenants, {:pool, external_id}}
  end

  def manager_name(external_id) do
    {PgEdge.Registry.Tenants, {:manager, external_id}}
  end

  @spec get_sup_pid(binary) :: pid() | :undefined
  def get_sup_pid(tenant) do
    supervisor_name(tenant)
    |> :syn.whereis_name()
  end

  @spec get_pool_pid(String.t()) :: pid() | :undefined
  def get_pool_pid(tenant) do
    pool_name(tenant)
    |> Registry.whereis_name()
  end

  @spec get_manager_pid(String.t()) :: pid() | :undefined
  def get_manager_pid(tenant) do
    manager_name(tenant)
    |> Registry.whereis_name()
  end

  ## Internal functions

  @spec start_pool(String.t()) ::
          {:ok, pid} | {:error, {:already_started, pid()} | :tenant_not_found}
  defp start_pool(tenant) do
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

        pool_spec = [
          name: {:via, :syn, pool_name(tenant)},
          worker_module: PgEdge.DbHandler,
          size: pool_size,
          max_overflow: 0
        ]

        auth = %{
          host: String.to_charlist(db_host),
          port: db_port,
          user: db_user,
          database: db_database,
          password: fn -> db_pass end,
          application_name: "pg_edge"
        }

        args = %{tenant: tenant, auth: auth, pool_spec: pool_spec, pool_size: pool_size}

        DynamicSupervisor.start_child(
          {:via, PartitionSupervisor, {PgEdge.DynamicSupervisor, self()}},
          {PgEdge.TenantSupervisor, args}
        )

      _ ->
        Logger.error("Can't find tenant with external_id #{tenant}")
        {:error, :tenant_not_found}
    end
  end
end
