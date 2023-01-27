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
          name: pool_name(external_id),
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
          :poolboy.child_spec(:worker, pool_spec, %{tenant: external_id, auth: auth})
        )

      _ ->
        Logger.error("Can't find tenant with external_id #{external_id}")
        {:error, :tenant_not_found}
    end
  end

  # TODO: implement stop_pool
  def stop_pool(_), do: :not_implemented

  @spec pool_name(any) :: {:via, Registry, {PgEdge.Registry.DbPool, any}}
  def pool_name(external_id) do
    {:via, Registry, {PgEdge.Registry.DbPool, external_id}}
  end
end
