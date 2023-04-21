defmodule Supavisor.CDC.Change do
  @moduledoc """
  This module is a struct that represents one changed row in a Sequin owned
  table in a customer database.
  """

  @type t :: %__MODULE__{
          table: String.t(),
          operation: operation(),
          payload: map()
        }

  @type operation :: :insert | :update | :delete

  @enforce_keys [:table, :operation, :payload]
  defstruct [:table, :operation, :payload]
end
