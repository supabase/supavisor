defmodule Supavisor.Errors.MaxProxyConnectionsReachedError do
  @moduledoc """
  This error is returned when the proxy connection limit is reached.
  """

  use Supavisor.Error, [:limit, code: "EMAXPROXYCONN"]

  @type t() :: %__MODULE__{
          limit: pos_integer(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{limit: limit}) do
    "max proxy connections reached, limit: #{inspect(limit)}"
  end
end
