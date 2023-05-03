defmodule Supavisor.Repo.Migrations.CreateSchema do
  use Ecto.Migration

  def change do
    execute """
              create schema if not exists _supavisor;
            """,
            """
              drop schema if exists _supavisor cascade;
            """
  end
end
