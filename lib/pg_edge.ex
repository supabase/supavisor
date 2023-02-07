defmodule PgEdge do
  @moduledoc false
  require Logger
  alias PgEdge.{Tenants, Tenants.Tenant}

  @spec start_pool(String.t()) :: {:ok, pid} | {:error, any}
  def start_pool(external_id) do
    Logger.debug("Starting pool for #{external_id}")

    case Tenants.get_tenant_by_external_id(external_id) do
      %Tenant{} = tenant ->
        %{
          db_host: db_host,
          db_port: db_port,
          db_user: db_user,
          db_database: db_database,
          db_password: db_pass,
          pool_size: pool_size
        } = tenant

        pool_spec = [
          name: {:via, :syn, pool_name(external_id)},
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

        DynamicSupervisor.start_child(
          {:via, PartitionSupervisor, {PgEdge.DynamicSupervisor, self()}},
          %{
            id: {:pool, external_id},
            start: {:poolboy, :start_link, [pool_spec, %{tenant: external_id, auth: auth}]},
            restart: :transient
          }
        )

      _ ->
        Logger.error("Can't find tenant with external_id #{external_id}")
        {:error, :tenant_not_found}
    end
  end

  @spec pool_name(String.t()) :: {:via, :syn, {:pool, String.t()}}
  def pool_name(external_id) do
    {:pool, external_id}
  end

  def stop_pool(external_id) do
    pool_name(external_id)
    |> :syn.whereis_name()
    |> DynamicSupervisor.stop()
  end

  @spec get_pool_pid(String.t()) :: pid() | :undefined
  def get_pool_pid(external_id) do
    pool_name(external_id)
    |> :syn.whereis_name()
  end
end
