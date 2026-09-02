defmodule Supavisor.Repo.Migrations.AddServerIdleTimeoutToUsers do
  use Ecto.Migration

  def change do
    alter table("users", prefix: "_supavisor") do
      add(:server_idle_timeout, :integer, null: false, default: 300_000)
    end
  end
end
