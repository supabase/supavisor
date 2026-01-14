defmodule Supavisor.Errors.StartupMessageError do
  @moduledoc """
  This error is returned when client sends an invalid startup message
  """

  use Supavisor.Error, [:reason, code: "ESTARTUPMESSAGE"]

  @type t() :: %__MODULE__{
          reason: term(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{reason: reason}) do
    "Invalid startup message: #{inspect(reason)}"
  end

  @impl Supavisor.Error
  def postgres_error(error) do
    Supavisor.Error.protocol_error("FATAL", "08P01", message(error))
  end
end
