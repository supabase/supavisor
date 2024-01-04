defmodule Supavisor.TenantsTest do
  use Supavisor.DataCase

  alias Supavisor.Tenants

  describe "tenants" do
    alias Supavisor.Tenants.{Tenant, User}

    import Supavisor.TenantsFixtures

    @invalid_attrs %{
      db_database: nil,
      db_host: nil,
      external_id: nil,
      default_parameter_status: nil,
      allow_list: ["foo", "bar"]
    }

    test "get_tenant!/1 returns the tenant with given id" do
      tenant = tenant_fixture()
      assert Tenants.get_tenant!(tenant.id) |> Repo.preload(:users) == tenant
    end

    test "create_tenant/1 with valid data creates a tenant" do
      user_valid_attrs = %{
        "db_user" => "some db_user",
        "db_password" => "some db_password",
        "pool_size" => 3,
        "require_user" => true,
        "mode_type" => "transaction"
      }

      valid_attrs = %{
        db_host: "some db_host",
        db_port: 42,
        db_database: "some db_database",
        external_id: "dev_tenant",
        default_parameter_status: %{"server_version" => "15.0"},
        require_user: true,
        users: [user_valid_attrs],
        allow_list: ["71.209.249.38/32"]
      }

      assert {:ok, %Tenant{users: [%User{} = user]} = tenant} = Tenants.create_tenant(valid_attrs)
      assert tenant.db_database == "some db_database"
      assert tenant.db_host == "some db_host"
      assert tenant.db_port == 42
      assert tenant.external_id == "dev_tenant"
      assert tenant.allow_list == ["71.209.249.38/32"]
      assert user.db_password == "some db_password"
      assert user.db_user == "some db_user"
      assert user.pool_size == 3
    end

    test "create_tenant/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Tenants.create_tenant(@invalid_attrs)
    end

    test "update_tenant/2 with invalid data returns error changeset" do
      tenant = tenant_fixture()
      assert {:error, %Ecto.Changeset{}} = Tenants.update_tenant(tenant, @invalid_attrs)
      assert tenant == Tenants.get_tenant!(tenant.id) |> Repo.preload(:users)
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

    test "get_user/4" do
      _tenant = tenant_fixture()
      assert {:error, :not_found} = Tenants.get_user(:single, "no_user", "no_tenant", "")

      assert {:ok, %{tenant: _, user: _}} =
               Tenants.get_user(:single, "postgres", "dev_tenant", "")
    end
  end

  describe "clusters" do
    alias Supavisor.Tenants.Cluster

    import Supavisor.TenantsFixtures

    @invalid_attrs %{active: nil, alias: nil}
    @valid_attrs %{active: true, alias: "some_alias"}

    test "list_clusters/0 returns all clusters" do
      cluster = cluster_fixture()
      assert Tenants.list_clusters() |> Repo.preload(:cluster_tenants) == [cluster]
    end

    test "get_cluster!/1 returns the cluster with given id" do
      cluster = cluster_fixture()
      assert Tenants.get_cluster!(cluster.id) |> Repo.preload(:cluster_tenants) == cluster
    end

    test "create_cluster/1 with valid data creates a cluster" do
      assert {:ok, %Cluster{} = cluster} = Tenants.create_cluster(@valid_attrs)
      assert cluster.active == true
    end

    test "create_cluster/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Tenants.create_cluster(@invalid_attrs)
    end

    test "update_cluster/2 with valid data updates the cluster" do
      cluster = cluster_fixture()

      assert {:ok, %Cluster{} = cluster} = Tenants.update_cluster(cluster, @valid_attrs)
      assert cluster.active == true
    end

    test "update_cluster/2 with invalid data returns error changeset" do
      cluster = cluster_fixture()
      assert {:error, %Ecto.Changeset{}} = Tenants.update_cluster(cluster, @invalid_attrs)
      assert cluster == Tenants.get_cluster!(cluster.id) |> Repo.preload(:cluster_tenants)
    end

    test "delete_cluster/1 deletes the cluster" do
      cluster = cluster_fixture()
      assert {:ok, %Cluster{}} = Tenants.delete_cluster(cluster)
      assert_raise Ecto.NoResultsError, fn -> Tenants.get_cluster!(cluster.id) end
    end

    test "change_cluster/1 returns a cluster changeset" do
      cluster = cluster_fixture()
      assert %Ecto.Changeset{} = Tenants.change_cluster(cluster)
    end
  end
end
