defmodule Supavisor.Repo.Migrations.AddTenantIpVersion do
  use Ecto.Migration

  def up do
    alter table("tenants", prefix: "_supavisor") do
      add(:ip_version, :string, null: false)
    end
  end

  def down do
    alter table("tenants", prefix: "_supavisor") do
      remove(:ip_version)
    end
  end
end
