defmodule Supavisor.CDC.Error do
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
