defmodule Supavisor.Repo.Migrations.AddIdleTimeoutDownstream do
  use Ecto.Migration

  def change do
    alter table("tenants", prefix: "_supavisor") do
      add(:idle_timeout_downstream, :integer, null: false, default: 10_000)
    end
  end
end
