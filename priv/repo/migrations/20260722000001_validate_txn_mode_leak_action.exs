defmodule Supavisor.Repo.Migrations.ValidateTxnModeLeakAction do
  use Ecto.Migration

  @disable_ddl_transaction true

  def up do
    execute("""
    ALTER TABLE _supavisor.tenants
      VALIDATE CONSTRAINT txn_mode_leak_action_values
    """)
  end

  def down do
    :ok
  end
end
