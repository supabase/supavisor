defmodule Supavisor.Repo.Migrations.AddSniHost do
  use Ecto.Migration

  def up do
    alter table("tenants", prefix: "_supavisor") do
      add(:sni_hostname, :string, null: true)
    end
  end

  def down do
    alter table("tenants", prefix: "_supavisor") do
      remove(:sni_hostname)
    end
  end
end
