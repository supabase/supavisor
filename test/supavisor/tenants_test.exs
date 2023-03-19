defmodule Supavisor.TenantsTest do
  use Supavisor.DataCase

  alias Supavisor.Tenants

  describe "tenants" do
    alias Supavisor.Tenants.Tenant

    import Supavisor.TenantsFixtures

    @invalid_attrs %{
      db_database: nil,
      db_host: nil,
      db_password: nil,
      db_port: nil,
      db_user: nil,
      external_id: nil,
      pool_size: nil
    }

    test "get_tenant!/1 returns the tenant with given id" do
      tenant = tenant_fixture()
      assert Tenants.get_tenant!(tenant.id) == tenant
    end

    test "create_tenant/1 with valid data creates a tenant" do
      valid_attrs = %{
        db_database: "some db_database",
        db_host: "some db_host",
        db_password: "some db_password",
        db_port: 42,
        db_user: "some db_user",
        external_id: "dev_tenant",
        pool_size: 42
      }

      assert {:ok, %Tenant{} = tenant} = Tenants.create_tenant(valid_attrs)
      assert tenant.db_database == "some db_database"
      assert tenant.db_host == "some db_host"
      assert tenant.db_password == "some db_password"
      assert tenant.db_port == 42
      assert tenant.db_user == "some db_user"
      assert tenant.external_id == "dev_tenant"
      assert tenant.pool_size == 42
    end

    test "create_tenant/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Tenants.create_tenant(@invalid_attrs)
    end

    test "update_tenant/2 with valid data updates the tenant" do
      tenant = tenant_fixture()

      update_attrs = %{
        db_database: "some updated db_database",
        db_host: "some updated db_host",
        db_password: "some updated db_password",
        db_port: 43,
        db_user: "some updated db_user",
        external_id: "some updated external_id",
        pool_size: 43
      }

      assert {:ok, %Tenant{} = tenant} = Tenants.update_tenant(tenant, update_attrs)
      assert tenant.db_database == "some updated db_database"
      assert tenant.db_host == "some updated db_host"
      assert tenant.db_password == "some updated db_password"
      assert tenant.db_port == 43
      assert tenant.db_user == "some updated db_user"
      assert tenant.external_id == "some updated external_id"
      assert tenant.pool_size == 43
    end

    test "update_tenant/2 with invalid data returns error changeset" do
      tenant = tenant_fixture()
      assert {:error, %Ecto.Changeset{}} = Tenants.update_tenant(tenant, @invalid_attrs)
      assert tenant == Tenants.get_tenant!(tenant.id)
    end

    test "delete_tenant/1 deletes the tenant" do
      tenant = tenant_fixture()
      assert {:ok, %Tenant{}} = Tenants.delete_tenant(tenant)
      assert_raise Ecto.NoResultsError, fn -> Tenants.get_tenant!(tenant.id) end
    end

    test "change_tenant/1 returns a tenant changeset" do
      tenant = tenant_fixture()
      assert %Ecto.Changeset{} = Tenants.change_tenant(tenant)
    end
  end
end
