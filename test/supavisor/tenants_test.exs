defmodule Supavisor.TenantsTest do
  use Supavisor.DataCase

  alias Supavisor.Tenants
  alias Supavisor.Tenants.{Cluster, Tenant, User}
  import Supavisor.TenantsFixtures

  describe "tenants" do
    @invalid_attrs %{
      db_database: nil,
      db_host: nil,
      external_id: nil,
      default_parameter_status: nil,
      allow_list: ["foo", "bar"]
    }

    test "list_tenants/0 returns all tenants" do
      tenants = Tenants.list_tenants()

      assert Enum.all?(1..10, fn i ->
               "cluster_pool_tenant_#{i}" in Enum.map(tenants, & &1.external_id)
             end)
    end

    test "get_tenant!/1 returns the tenant with given id" do
      tenant = tenant_fixture()
      assert Tenants.get_tenant!(tenant.id) |> Repo.preload(:users) == tenant
    end

    test "get_tenant_by_external_id/1 returns the tenant with given external_id" do
      tenant = tenant_fixture()
      assert Tenants.get_tenant_by_external_id(tenant.external_id) == tenant
    end

    test "get_cluster_by_alias/1 returns the cluster with given alias" do
      cluster = cluster_fixture()
      assert Tenants.get_cluster_by_alias(cluster.alias) == cluster
    end

    test "get_tenant_cache/2 returns a tenant from cache" do
      tenant = tenant_fixture(%{external_id: "cache_tenant", sni_hostname: "cache.example.com"})

      Cachex.put(
        Supavisor.Cache,
        {:tenant_cache, "cache_tenant", "cache.example.com"},
        {:cached, tenant}
      )

      assert Tenants.get_tenant_cache("cache_tenant", "cache.example.com") |> Repo.preload(:users) ==
               tenant
    end

    test "get_tenant_cache/2 fetches and caches a tenant after it expires" do
      tenant = tenant_fixture(%{external_id: "cache_tenant", sni_hostname: "cache.example.com"})

      Cachex.put(Supavisor.Cache, {:tenant_cache, "cache_tenant", "cache.example.com"}, tenant,
        ttl: 10
      )

      Process.sleep(50)

      assert Tenants.get_tenant_cache("cache_tenant", "cache.example.com") |> Repo.preload(:users) ==
               tenant
    end

    test "get_tenant/2 returns the tenant with given external_id and sni_hostname" do
      tenant = tenant_fixture(%{external_id: "sni_tenant", sni_hostname: "sni.example.com"})

      assert Tenants.get_tenant("sni_tenant", "sni.example.com") |> Repo.preload(:users) ==
               tenant
    end

    test "get_tenant/2 returns the tenant with sni_hostname when external_id is nil" do
      tenant = tenant_fixture(%{sni_hostname: "sni.example.com"})

      assert Tenants.get_tenant(nil, "sni.example.com") |> Repo.preload(:users) ==
               tenant
    end

    test "get_tenant/2 when both provided external_id and sni are nil" do
      assert Tenants.get_tenant(nil, nil) == nil
    end

    test "get_tenant/2 returns nil if tenant is not found" do
      assert Tenants.get_tenant("no_tenant", "no_host") == nil
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

    test "update_tenant_ps/2 updates the tenant's default_parameter_status" do
      _tenant = tenant_fixture()
      default_parameter_status = %{"server_version" => "17.0"}

      assert {:ok, %Tenant{default_parameter_status: ^default_parameter_status}} =
               Tenants.update_tenant_ps("dev_tenant", default_parameter_status)
    end

    test "delete_tenant_by_external_id/1 returns true tenant is found and deleted by a given external_id" do
      tenant = tenant_fixture()
      assert Tenants.delete_tenant_by_external_id(tenant.external_id) == true
    end

    test "delete_tenant_by_external_id/1 returns false if no tenant is found from a given external_id" do
      assert Tenants.delete_tenant_by_external_id("dev_tenant") == false
    end

    test "delete_cluster_by_alias/1 returns true if cluster is found and deleted by a given alias" do
      cluster = cluster_fixture()
      assert Tenants.delete_cluster_by_alias(cluster.alias) == true
    end

    test "delete_cluster_by_alias/1 returns false if no cluster is found from a given alias" do
      assert Tenants.delete_cluster_by_alias("some_alias") == false
    end
  end

  describe "clusters" do
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

  test "db_password is redacted" do
    refute inspect(%Tenant{users: [%User{db_password: "zxc"}]}) =~ "zxc"
  end
end
