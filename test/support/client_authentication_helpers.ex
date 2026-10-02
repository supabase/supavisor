defmodule Supavisor.Support.ClientAuthenticationHelpers do
  @moduledoc """
  Shared helpers for seeding `Supavisor.ClientAuthentication`'s validation-secrets cache in tests.
  """

  alias Supavisor.ClientAuthentication
  alias Supavisor.ClientAuthentication.ValidationSecrets
  alias Supavisor.Secrets.PasswordSecrets

  @doc "Builds a throwaway `ValidationSecrets` for cache-seeding in tests."
  @spec build_validation_secrets(String.t()) :: ValidationSecrets.t()
  def build_validation_secrets(user) do
    ValidationSecrets.from_password_secrets(%PasswordSecrets{user: user, password: "pw"})
  end

  @doc "Seeds the local validation-secrets cache for `tenant`/`user`."
  @spec seed_cache(String.t(), String.t()) :: any()
  def seed_cache(tenant, user) do
    ClientAuthentication.put_validation_secrets(tenant, user, build_validation_secrets(user))
  end
end
