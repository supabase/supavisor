defmodule Supavisor.Protocol.PreparedStatements.PreparedStatement do
  @moduledoc """
  Represents a prepared statement.
  """

  defstruct [:parse_pkt, :name]

  @type t() :: %__MODULE__{
          parse_pkt: Supavisor.Protocol.Client.Pkt.t(),
          name: String.t()
        }
end
