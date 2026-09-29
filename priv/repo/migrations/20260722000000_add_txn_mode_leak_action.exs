defmodule Supavisor.Repo.Migrations.AddTxnModeLeakAction do
  use Ecto.Migration

  def change do
    alter table("tenants", prefix: "_supavisor") do
      add(:txn_mode_leak_action, :string, null: false, default: "ignore")
    end

    create(
      constraint(
        "tenants",
        :txn_mode_leak_action_values,
        check: "txn_mode_leak_action IN ('ignore', 'log', 'error')",
        prefix: "_supavisor",
        validate: false
      )
    )
  end
end
