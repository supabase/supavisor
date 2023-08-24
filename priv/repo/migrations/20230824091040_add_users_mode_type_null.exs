defmodule Supavisor.Repo.Migrations.AddUsersModeTypeNull do
  use Ecto.Migration

  def change do
    execute("ALTER TABLE _supavisor.users ALTER COLUMN mode_type DROP NOT NULL")
  end
end
