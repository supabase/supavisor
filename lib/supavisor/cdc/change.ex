defmodule Supavisor.CDC.Change do
  @moduledoc """
  This module is a struct that represents one changed row in a Sequin owned
  table in a customer database.
  """

  @type t :: %__MODULE__{
          table_name: String.t(),
          operation: operation(),
          record: map(),
          inserted_at: DateTime.t()
        }

  @type operation :: :insert | :update | :delete

  @enforce_keys [:table_name, :operation, :record, :inserted_at]
  defstruct [:table_name, :operation, :record, :inserted_at]
end
