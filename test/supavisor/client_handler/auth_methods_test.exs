defmodule Supavisor.ClientHandler.AuthMethodsTest do
  use ExUnit.Case, async: false

  alias Supavisor.ClientHandler.AuthMethods
  alias Supavisor.Errors.SslRequiredError
  alias Supavisor.Tenants.Tenant

  describe "fetch_authentication_method/5" do
    test "uses SCRAM without TLS" do
      tenant = %Tenant{use_jit: false, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, false, false, false, "user") ==
               {:ok, :scram_sha_256}
    end

    test "uses SCRAM over TLS by default" do
      tenant = %Tenant{use_jit: false, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, false, "user") ==
               {:ok, :scram_sha_256}
    end

    test "uses cleartext password over TLS when cleartext_auth_over_tls is enabled for the tenant" do
      tenant = %Tenant{use_jit: false, feature_flags: %{"cleartext_auth_over_tls" => true}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, false, "user") ==
               {:ok, :password}
    end

    test "uses cleartext password over TLS when cleartext_auth_over_tls is enabled globally" do
      original = Application.get_env(:supavisor, Supavisor.FeatureFlag, %{})

      Application.put_env(
        :supavisor,
        Supavisor.FeatureFlag,
        Map.put(original, "cleartext_auth_over_tls", true)
      )

      on_exit(fn -> Application.put_env(:supavisor, Supavisor.FeatureFlag, original) end)

      tenant = %Tenant{use_jit: false, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, false, "user") ==
               {:ok, :password}
    end

    test "tenant flag overrides the global setting" do
      original = Application.get_env(:supavisor, Supavisor.FeatureFlag, %{})

      Application.put_env(
        :supavisor,
        Supavisor.FeatureFlag,
        Map.put(original, "cleartext_auth_over_tls", true)
      )

      on_exit(fn -> Application.put_env(:supavisor, Supavisor.FeatureFlag, original) end)

      tenant = %Tenant{use_jit: false, feature_flags: %{"cleartext_auth_over_tls" => false}}

      assert AuthMethods.fetch_authentication_method(tenant, false, true, false, "user") ==
               {:ok, :scram_sha_256}
    end

    test "uses JIT over TLS regardless of cleartext_auth_over_tls" do
      tenant = %Tenant{use_jit: true, feature_flags: %{"cleartext_auth_over_tls" => true}}

      assert AuthMethods.fetch_authentication_method(tenant, true, true, false, "user") ==
               {:ok, :jit}
    end

    test "rejects JIT without TLS" do
      tenant = %Tenant{use_jit: true, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, true, false, false, "user") ==
               {:error, %SslRequiredError{user: "user"}}
    end

    test "uses cleartext password when forced" do
      tenant = %Tenant{use_jit: false, feature_flags: %{}}

      assert AuthMethods.fetch_authentication_method(tenant, false, false, true, "user") ==
               {:ok, :password}
    end
  end
end
