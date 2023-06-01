defmodule Supavisor.Repo.Migrations.AddTenantPgVersion do
  use Ecto.Migration

  def up do
    alter table("tenants", prefix: "_supavisor") do
      add(:pg_version, :string, default: "0.0", null: false)
    end
  end

  def down do
    alter table("tenants", prefix: "_supavisor") do
      remove(:pg_version)
    end
  end
end
