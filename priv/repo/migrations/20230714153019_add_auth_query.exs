defmodule Supavisor.Repo.Migrations.AddAuthQuery do
  use Ecto.Migration

  def up do
    alter table("tenants", prefix: "_supavisor") do
      add(:require_user, :boolean, null: false, default: true)
      add(:auth_query, :string, null: true)
    end
  end

  def down do
    alter table("tenants", prefix: "_supavisor") do
      remove(:auth_query)
    end
  end
end
