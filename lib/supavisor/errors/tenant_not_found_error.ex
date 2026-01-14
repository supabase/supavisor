defmodule Supavisor.Errors.TenantNotFoundError do
  @moduledoc """
  This error is returned when the requested tenant or user is not found
  """

  use Supavisor.Error, [:reason, :type, :user, :tenant_or_alias, code: "ETENANTNOTFOUND"]

  @type t() :: %__MODULE__{
          reason: term() | nil,
          type: atom() | nil,
          user: binary() | nil,
          tenant_or_alias: binary() | nil,
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{reason: nil}) do
    "tenant or user not found"
  end

  def error_message(%{reason: reason, type: type, user: user, tenant_or_alias: tenant_or_alias}) do
    "user not found: #{inspect(reason)} #{inspect({type, user, tenant_or_alias})}"
  end

  @impl Supavisor.Error
  def log_message(%{reason: nil}), do: "Tenant not found"

  def log_message(%{reason: reason, type: type, user: user, tenant_or_alias: tenant_or_alias}) do
    "User not found: #{inspect(reason)} #{inspect({type, user, tenant_or_alias})}"
  end

  @impl Supavisor.Error
  def is_auth_error(%{reason: nil}), do: false
  def is_auth_error(_), do: true
end
