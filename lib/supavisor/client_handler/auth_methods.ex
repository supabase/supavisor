defmodule Supavisor.ClientHandler.AuthMethods do
  @moduledoc """
  Determines the authentication method based on tenant configuration and client options.
  """

  alias Supavisor.ClientAuthentication
  alias Supavisor.ClientHandler.AuthMethods.Jit
  alias Supavisor.Errors.SslRequiredError
  alias Supavisor.Secrets.ManagerSecrets

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
  def fetch_authentication_method(tenant, client_jit, ssl?, user) do
    case {tenant.use_jit, client_jit, ssl?} do
      {false, _, _} -> {:ok, :scram_sha_256}
      {true, false, false} -> {:ok, :scram_sha_256}
      {true, false, true} -> {:ok, :password}
      {true, true, false} -> {:error, %SslRequiredError{user: user}}
      {true, true, true} -> {:ok, :jit}
    end
  end

  @doc """
  Handles an auth failure in the different authentication methods.
  """
  def handle_auth_failure(%Jit.Context{}, _err) do
    :ok
  end

  def handle_auth_failure(%_{tenant: %{require_user: true}}, _err) do
    :ok
  end

  def handle_auth_failure(context, %Supavisor.Errors.WrongPasswordError{}) do
    ClientAuthentication.handle_wrong_password(
      context.id,
      context.tenant,
      ManagerSecrets.from_manager_user(context.user)
    )
  end

  def handle_auth_failure(_, _) do
    :ok
  end
end
