defmodule Supavisor.ClientHandler.AuthMethods do
  @moduledoc """
  Determines the authentication method based on tenant configuration and client options.
  """

  alias Supavisor.Errors.SslRequiredError
  alias Supavisor.FeatureFlag

  @doc """
  Fetches potential authentication methods for the tenant. If the authentication
  methods enabled for the user require SSL, returns an error if SSL is not enabled.

  When `client_jit` is true (client passed `--jit=true` in options) and the tenant
  has `use_jit` enabled, returns `:jit` to route to the dedicated JIT auth module.

  Over TLS, cleartext password authentication is used unless the
  `cleartext_auth_over_tls` feature flag is disabled, in which case SCRAM is used.
  """
  @spec fetch_authentication_method(
          Supavisor.Tenants.Tenant.t(),
          client_jit :: boolean(),
          ssl? :: boolean(),
          String.t()
        ) ::
          {:ok, :jit | :password | :scram_sha_256} | {:error, SslRequiredError.t()}
  def fetch_authentication_method(tenant, client_jit, ssl?, user) do
    case {tenant.use_jit, client_jit, ssl?} do
      {_, false, false} -> {:ok, :scram_sha_256}
      {_, false, true} -> {:ok, tls_authentication_method(tenant)}
      {true, true, false} -> {:error, %SslRequiredError{user: user}}
      {true, true, true} -> {:ok, :jit}
    end
  end

  defp tls_authentication_method(tenant) do
    if FeatureFlag.enabled?(tenant, "cleartext_auth_over_tls"),
      do: :password,
      else: :scram_sha_256
  end
end
