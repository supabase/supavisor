defmodule Supavisor.Errors.CheckoutTimeoutError do
  @moduledoc """
  This error is returned when unable to check out a connection from the pool due to timeout.
  This happens when all connections in the pool are busy and none become available within the checkout timeout period.
  Applies to both session and transaction modes.
  """

  use Supavisor.Error, [:mode, :timeout_ms, code: "ECHECKOUTTIMEOUT"]

  @type t() :: %__MODULE__{
          mode: :session | :transaction,
          timeout_ms: non_neg_integer(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{mode: mode, timeout_ms: timeout_ms}) do
    mode_str = mode |> to_string() |> String.capitalize()

    """
    Pool checkout timeout. Request was dropped after #{timeout_ms}ms in #{mode_str} mode. \
    This means requests are coming in and your connection pool cannot serve them fast enough. \
    You can address this by:

      1. Ensuring your database is available and that you can connect to it
      2. Tracking down slow queries and making sure they are running fast enough
      3. Increasing the pool_size (although this increases resource consumption)
      4. Upgrading your database

    Review the Supabase performance tuning guide for Postgres: https://supabase.com/docs/guides/platform/performance\
    """
  end
end
