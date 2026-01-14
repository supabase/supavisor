defmodule Supavisor.Errors.MaxClientConnectionsError do
  @moduledoc """
  This error is returned when the client connection limit is reached in a transaction mode pool
  """

  use Supavisor.Error, [:limit, code: "EMAXCLIENTCONN"]

  @type t() :: %__MODULE__{
          limit: non_neg_integer(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{limit: limit}) do
    "max client connections reached, limit: #{inspect(limit)}"
  end
end
