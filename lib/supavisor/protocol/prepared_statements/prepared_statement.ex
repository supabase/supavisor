defmodule Supavisor.Protocol.PreparedStatements.PreparedStatement do
  @moduledoc """
  Represents a prepared statement
  """

  defstruct [:parse_pkt, :name]

  @type t() :: %__MODULE__{
          parse_pkt: binary(),
          name: String.t()
        }
end
