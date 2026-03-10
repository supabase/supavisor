defmodule Supavisor.Errors.AuthProtocolError do
  @moduledoc """
  This error is returned when there's a protocol violation during authentication,
  such as unexpected messages or decode errors.
  """

  use Supavisor.Error, [:details, :context, code: "EAUTHPROTOCOL"]

  @type t() :: %__MODULE__{
          details: {:unexpected_message, term()} | {:decode_error, term()},
          context: atom() | nil,
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(_error) do
    "protocol violation during authentication"
  end

  @impl Supavisor.Error
  def log_message(%{details: {:unexpected_message, details}, context: context}) do
    "#{context_description(context)} unexpected message during authentication: #{inspect(details)}"
  end

  def log_message(%{details: {:decode_error, error}, context: context}) do
    "#{context_description(context)} auth decode error: #{inspect(error)}"
  end

  @impl Supavisor.Error
  def postgres_error(error) do
    Supavisor.Error.protocol_error("FATAL", "08P01", message(error))
  end

  @impl Supavisor.Error
  def is_auth_error(_), do: true

  defp context_description(:auth_md5_wait), do: "MD5"
  defp context_description(:auth_scram_first_wait), do: "SCRAM first"
  defp context_description(:auth_scram_final_wait), do: "SCRAM final"
  defp context_description(other), do: inspect(other)
end
