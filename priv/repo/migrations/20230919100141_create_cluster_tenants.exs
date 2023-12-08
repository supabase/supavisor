defmodule Supavisor.Repo.Migrations.CreateClusterTenants do
  use Ecto.Migration

  def change do
    create table("cluster_tenants", primary_key: false, prefix: "_supavisor") do
      add(:id, :binary_id, primary_key: true)
      add(:type, :string, null: false)
      add(:active, :boolean, default: false, null: false)

      add(
        :cluster_alias,
        references(:clusters, on_delete: :delete_all, type: :string, column: :alias)
      )

      add(
        :tenant_external_id,
        references(:tenants, type: :string, column: :external_id)
      )

      timestamps()
    end

    create(
      constraint(
        :cluster_tenants,
        :type,
        check: "type IN ('read', 'write')"
      )
    )

    create(
      index(:cluster_tenants, [:tenant_external_id],
        unique: true,
        prefix: "_supavisor"
      )
    )
  end
end
