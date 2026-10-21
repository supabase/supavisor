defmodule Supavisor.Repo.Migrations.AddTenantLogConnections do
  use Ecto.Migration

  def change do
    alter table("tenants", prefix: "_supavisor") do
      add(:log_connections, :boolean, null: false, default: true)
    end
  end
end
