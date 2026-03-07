defmodule Supavisor.ClientHandler.Auth do
  @moduledoc """
  Helpers that work for more than one authentication method
  """

  require Logger

  alias Supavisor.ClientHandler.Auth.PasswordSecrets
  alias Supavisor.Errors.SslRequiredError

  @doc """
  Fetches potential authentication methods for the tenant. If the authentication
  methods enabled for the user require SSL, returns an error if SSL is not enabled.

  When `client_jit` is true (client passed `--jit=true` in options) and the tenant
  has `use_jit` enabled, returns `:jit` to route to the dedicated JIT auth module.
  """
  @spec fetch_authentication_method(
          %{use_jit: boolean()},
          client_jit :: boolean(),
          ssl? :: boolean(),
          String.t()
        ) ::
          {:ok, :jit | :password | :scram_sha_256} | {:error, SslRequiredError.t()}
  def fetch_authentication_method(%{use_jit: true}, _client_jit = true, ssl?, user) do
    if ssl? do
      {:ok, :jit}
    else
      {:error, %SslRequiredError{user: user}}
    end
  end

  def fetch_authentication_method(%{use_jit: true}, _client_jit = false, ssl?, user) do
    if ssl? do
      {:ok, :password}
    else
      {:error, %SslRequiredError{user: user}}
    end
  end

  def fetch_authentication_method(%{use_jit: false}, _client_jit, _ssl?, _user) do
    {:ok, :scram_sha_256}
  end

  @doc """
  Resolves the secrets to use for upstream database authentication.

  For `require_user: true` tenants, the client-facing SCRAM validation uses
  SASLSecrets with a random salt, which can't be used to authenticate upstream
  (Postgres has its own salt). Instead, we use PasswordSecrets with the plaintext
  password so DbHandler can derive SCRAM keys from whatever salt Postgres sends.

  For other tenants, the final_secrets from client auth are used as-is.
  """
  @spec resolve_upstream_secrets(
          Supavisor.ClientHandler.Auth.PasswordSecrets.t()
          | Supavisor.ClientHandler.Auth.SASLSecrets.t(),
          %{require_user: boolean()}
        ) :: map()
  def resolve_upstream_secrets(_final_secrets, %{require_user: true} = auth) do
    %PasswordSecrets{user: auth.user, password: auth.password}
  end

  def resolve_upstream_secrets(final_secrets, _auth), do: final_secrets
end
