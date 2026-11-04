defmodule Supavisor.Errors.DirectSslRejectedError do
  @moduledoc """
  This error is returned when a client opens a direct SSL connection that can't be accepted
  """

  use Supavisor.Error, [:reason, code: "EDIRECTSSLREJECTED"]

  @type reason() :: :no_certificate | :no_alpn

  @type t() :: %__MODULE__{
          reason: reason(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{reason: :no_certificate}) do
    "direct SSL connection rejected: no server certificate configured"
  end

  def error_message(%{reason: :no_alpn}) do
    "received direct SSL connection request without ALPN protocol negotiation extension"
  end

  @impl Supavisor.Error
  def log_level(%{reason: :no_certificate}), do: :warning
  def log_level(%{reason: :no_alpn}), do: :error

  # Without a certificate the client is still waiting for a ServerHello, so there is
  # nothing we can send it
  @impl Supavisor.Error
  def postgres_error(%{reason: :no_certificate}), do: nil

  def postgres_error(%{reason: :no_alpn} = error) do
    Supavisor.Error.protocol_error("FATAL", "08P01", message(error))
  end

  @impl Supavisor.Error
  def fault(_), do: :user
end
