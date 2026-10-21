defmodule Supavisor.ClientHandler.AuthMethodsTest do
  use ExUnit.Case, async: false

  alias Supavisor.ClientHandler.AuthMethods
  alias Supavisor.Errors.SslRequiredError
  alias Supavisor.Tenants.Tenant

  describe "fetch_authentication_method/4" do
    test "uses SCRAM without TLS" do
      tenant = %Tenant{use_jit: false, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, false, false, "user") ==
               {:ok, :scram_sha_256}
    end

    test "uses cleartext password over TLS by default" do
      tenant = %Tenant{use_jit: false, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, "user") ==
               {:ok, :password}
    end

    test "uses SCRAM over TLS when scram_auth_over_tls is enabled for the tenant" do
      tenant = %Tenant{use_jit: false, feature_flags: %{"scram_auth_over_tls" => true}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, "user") ==
               {:ok, :scram_sha_256}
    end

    test "uses SCRAM over TLS when scram_auth_over_tls is enabled globally" do
      original = Application.get_env(:supavisor, Supavisor.FeatureFlag, %{})

      Application.put_env(
        :supavisor,
        Supavisor.FeatureFlag,
        Map.put(original, "scram_auth_over_tls", true)
      )

      on_exit(fn -> Application.put_env(:supavisor, Supavisor.FeatureFlag, original) end)

      tenant = %Tenant{use_jit: false, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, "user") ==
               {:ok, :scram_sha_256}
    end

    test "tenant flag overrides the global setting" do
      original = Application.get_env(:supavisor, Supavisor.FeatureFlag, %{})

      Application.put_env(
        :supavisor,
        Supavisor.FeatureFlag,
        Map.put(original, "scram_auth_over_tls", true)
      )

      on_exit(fn -> Application.put_env(:supavisor, Supavisor.FeatureFlag, original) end)

      tenant = %Tenant{use_jit: false, feature_flags: %{"scram_auth_over_tls" => false}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, "user") ==
               {:ok, :password}
    end

    test "uses JIT over TLS regardless of scram_auth_over_tls" do
      tenant = %Tenant{use_jit: true, feature_flags: %{"scram_auth_over_tls" => true}}

      assert AuthMethods.fetch_authentication_method(tenant, true, true, "user") ==
               {:ok, :jit}
    end

    test "rejects JIT without TLS" do
      tenant = %Tenant{use_jit: true, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, true, false, "user") ==
               {:error, %SslRequiredError{user: "user"}}
    end
  end
end
