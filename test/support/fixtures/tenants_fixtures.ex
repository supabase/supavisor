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
        db_password: "some db_password",
        db_port: 42,
        db_user: "some db_user",
        external_id: "dev_tenant",
        pool_size: 42
      })
      |> Supavisor.Tenants.create_tenant()

    tenant
  end
end
