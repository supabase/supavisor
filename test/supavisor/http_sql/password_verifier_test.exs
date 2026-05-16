defmodule Supavisor.HttpSql.PasswordVerifierTest do
  use Supavisor.DataCase, async: false

  import Supavisor.TenantsFixtures

  alias Supavisor.HttpSql.PasswordVerifier

  setup do
    tenant = tenant_fixture()
    tenant = Supavisor.Tenants.get_tenant_by_external_id(tenant.external_id)
    [user | _] = tenant.users
    {:ok, tenant: tenant, user: user}
  end

  describe "verify/3" do
    test "returns :ok for correct password", %{tenant: tenant, user: user} do
      # The fixture seeds db_user=\"postgres\", db_password=\"postgres\"
      assert :ok = PasswordVerifier.verify(tenant, user, "postgres")
    end

    test "returns {:error, :invalid_password} on wrong password", %{tenant: tenant, user: user} do
      assert {:error, :invalid_password} = PasswordVerifier.verify(tenant, user, "WRONG")
    end

    test "rejects an empty password", %{tenant: tenant, user: user} do
      assert {:error, :invalid_password} = PasswordVerifier.verify(tenant, user, "")
    end

    test "is case-sensitive", %{tenant: tenant, user: user} do
      assert {:error, :invalid_password} = PasswordVerifier.verify(tenant, user, "Postgres")
      assert {:error, :invalid_password} = PasswordVerifier.verify(tenant, user, "POSTGRES")
    end

    test "tolerates unicode passwords via saslprep", %{tenant: tenant, user: user} do
      # Right password still wins regardless of any side-effects.
      assert :ok = PasswordVerifier.verify(tenant, user, "postgres")
      assert {:error, :invalid_password} = PasswordVerifier.verify(tenant, user, "пароль")
    end
  end
end
