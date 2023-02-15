defmodule PgEdge do
  @moduledoc false
  require Logger
  alias PgEdge.{Tenants, Tenants.Tenant}

  @spec start_pool(String.t()) :: {:ok, pid} | {:error, any}
  def start_pool(tenant) do
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

  defdelegate subscribe(tenant), to: PgEdge.Manager

  @spec supervisor_name(String.t()) :: {:supervisor, String.t()}
  def supervisor_name(tenant) do
    {:supervisor, tenant}
  end

  @spec pool_name(String.t()) :: {:pool, String.t()}
  def pool_name(tenant) do
    {:pool, tenant}
  end

  def stop_pool(tenant) do
    supervisor_name(tenant)
    |> :syn.whereis_name()
    |> Supervisor.stop()
  end

  @spec get_pool_pid(String.t()) :: pid() | :undefined
  def get_pool_pid(tenant) do
    pool_name(tenant)
    |> :syn.whereis_name()
  end
end
