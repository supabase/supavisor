defmodule Supavisor.Repo.Migrations.AddClientIdleInTransactionTimeout do
  use Ecto.Migration

  def change do
    alter table("tenants", prefix: "_supavisor") do
      add(:client_idle_in_transaction_timeout, :integer, null: false, default: 0)
    end
  end
end
