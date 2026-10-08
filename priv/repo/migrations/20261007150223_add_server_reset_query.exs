defmodule Supavisor.Repo.Migrations.AddServerResetQuery do
  use Ecto.Migration

  def change do
    alter table("tenants", prefix: "_supavisor") do
      add(:server_reset_query, :string, default: "DISCARD ALL")
    end
  end
end
