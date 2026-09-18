defmodule Supavisor.Repo.Migrations.ValidateTxnModeSetAction do
  use Ecto.Migration

  @disable_ddl_transaction true

  def up do
    execute("""
    ALTER TABLE _supavisor.tenants
      VALIDATE CONSTRAINT txn_mode_set_action_values
    """)
  end

  def down do
    :ok
  end
end
