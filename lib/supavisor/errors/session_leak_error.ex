defmodule Supavisor.Errors.SessionLeakError do
  @moduledoc """
  This error is returned when a statement would leave session state on the backend
  in transaction mode and the tenant is configured to reject those.

  `leak` names what the statement leaves behind. Transaction-scoped variants
  (`SET LOCAL`, `SET TRANSACTION`, `ON COMMIT DROP`) are always allowed.
  """

  use Supavisor.Error, [:leak, code: "ESESSIONLEAK"]

  @type t() :: %__MODULE__{
          code: binary(),
          leak: Supavisor.PgParser.session_leak()
        }

  @impl Supavisor.Error
  def error_message(%{leak: leak}) do
    "#{Supavisor.Protocol.SetStatements.describe(leak)} is not allowed in transaction mode"
  end
end
