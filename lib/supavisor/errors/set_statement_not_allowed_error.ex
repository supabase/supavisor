defmodule Supavisor.Errors.SetStatementNotAllowedError do
  @moduledoc """
  This error is returned when a session-level SET statement is used in transaction mode
  and the tenant is configured to reject them.

  Transaction-scoped variants (`SET LOCAL`, `SET TRANSACTION`) are always allowed.
  """

  use Supavisor.Error, code: "ESETNOTALLOWED"

  @type t() :: %__MODULE__{
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(_error) do
    "session-level SET statements are not allowed in transaction mode"
  end
end
