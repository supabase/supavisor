defmodule Supavisor.CDC.Error do
  @moduledoc """
  Errors that can be returned by the CDC handler.

  These errors are emitted by the CDC handler and are translated into
  Postgres error packets so that they can be sent back to the client.

  See https://www.postgresql.org/docs/current/protocol-error-fields.html
  """

  @type t :: %__MODULE__{
          code: code,
          message: message,
          hint: hint
        }

  @type code :: :data_exception
  @type message :: String.t()
  @type hint :: String.t() | nil

  @enforce_keys [:code, :message]
  defstruct [:code, :message, :hint]
end
