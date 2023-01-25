defmodule PgEdge.Repo.Migrations.CreateTenants do
  use Ecto.Migration

  def change do
    create table(:tenants, primary_key: false, prefix: "pgedge") do
      add(:id, :binary_id, primary_key: true)
      add(:external_id, :string)
      add(:db_host, :string)
      add(:db_port, :integer)
      add(:db_user, :string)
      add(:db_database, :string)
      add(:db_password, :string)
      add(:pool_size, :integer)

      timestamps()
    end

    create(index(:tenants, [:external_id], unique: true, prefix: "pgedge"))
  end
end
