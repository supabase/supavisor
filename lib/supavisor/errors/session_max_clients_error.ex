defmodule Supavisor.Errors.SessionMaxClientsError do
  @moduledoc """
  This error is returned when the client connection limit is reached in a session mode pool.
  In session mode, max clients are limited to pool_size.
  """

  use Supavisor.Error, [:pool_size, code: "EMAXCLIENTSESSION"]

  @type t() :: %__MODULE__{
          pool_size: non_neg_integer(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{pool_size: pool_size}) do
    "max clients reached in session mode - max clients are limited to pool_size: #{inspect(pool_size)}"
  end
end
