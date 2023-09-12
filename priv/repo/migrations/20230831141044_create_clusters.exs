defmodule Supavisor.Repo.Migrations.CreateClusters do
  use Ecto.Migration

  def change do
    create table("clusters", primary_key: false, prefix: "_supavisor") do
      add(:id, :binary_id, primary_key: true)
      add(:is_active, :boolean, default: false, null: false)

      add(:cluster_tenants_id, :string)

      timestamps()
    end
  end
end
