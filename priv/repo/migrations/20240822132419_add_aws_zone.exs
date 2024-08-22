defmodule Supavisor.Repo.Migrations.AddAwsZone do
  use Ecto.Migration

  def change do
    alter table("tenants", prefix: "_supavisor") do
      add(:aws_zone, :string)
    end
  end
end
