defmodule PgEdge.TenantsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `PgEdge.Tenants` context.
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
        external_id: "some external_id",
        pool_size: 42
      })
      |> PgEdge.Tenants.create_tenant()

    tenant
  end
end
