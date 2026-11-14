defmodule Supavisor.Errors.SslHandshakeError do
  @moduledoc """
  This error is returned when SSL handshake fails during client connection
  """

  use Supavisor.Error, [:reason, code: "ESSLHANDSHAKE"]

  @type t() :: %__MODULE__{
          reason: term(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{reason: reason}) do
    "SSL handshake failed: #{inspect(reason)}"
  end

  # An overloaded handshake is refused with a TLS alert, sent by the ClientHandler.
  @impl Supavisor.Error
  def postgres_error(%{reason: :overloaded}), do: nil

  def postgres_error(error) do
    Supavisor.Error.protocol_error("FATAL", "08006", message(error))
  end

  @impl Supavisor.Error
  def log_level(%{reason: :overloaded}), do: :warning
  def log_level(_), do: :error

  @impl Supavisor.Error
  def fault(%{reason: :overloaded}), do: :supavisor
  def fault(_), do: :user
end
