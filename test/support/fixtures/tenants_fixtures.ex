defmodule Supavisor.TenantsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `Supavisor.Tenants` context.
  """

  @doc """
  Generate a tenant.
  """
  def tenant_fixture(attrs \\ %{}) do
    {:ok, tenant} =
      attrs
      |> Enum.into(%{
        db_database: "some db_database",
        db_host: "some db_host",
        db_port: 42,
        external_id: "dev_tenant",
        default_parameter_status: %{"server_version" => "15.0"},
        users: [
          %{
            "db_user" => "postgres",
            "db_password" => "postgres",
            "pool_size" => 3,
            "mode_type" => "transaction"
          }
        ]
      })
      |> Supavisor.Tenants.create_tenant()

    tenant
  end
end
