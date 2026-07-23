defmodule Supavisor.Repo.Migrations.AddTxnModeSetAction do
  use Ecto.Migration

  def change do
    alter table("tenants", prefix: "_supavisor") do
      add(:txn_mode_set_action, :string, null: false, default: "ignore")
    end

    create(
      constraint(
        "tenants",
        :txn_mode_set_action_values,
        check: "txn_mode_set_action IN ('ignore', 'log', 'error')",
        prefix: "_supavisor"
      )
    )
  end
end
