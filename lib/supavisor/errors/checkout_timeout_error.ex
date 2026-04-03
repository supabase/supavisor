defmodule Supavisor.Errors.CheckoutTimeoutError do
  @moduledoc """
  This error is returned when unable to check out a connection from the pool due to timeout.

  This happens when all connections in the pool are busy and none become available within
  the checkout timeout period. The error provides actionable guidance to help users
  diagnose and resolve connection pool exhaustion issues.

  Applies to both session and transaction modes, with mode-specific remediation hints.
  """

  use Supavisor.Error, [:mode, :timeout_ms, code: "ECHECKOUTTIMEOUT"]

  @type t() :: %__MODULE__{
          mode: :session | :transaction,
          timeout_ms: non_neg_integer(),
          code: binary()
        }

  @docs_url "https://supabase.com/docs/guides/database/connecting-to-postgres"

  @impl Supavisor.Error
  def error_message(%{mode: mode, timeout_ms: timeout_ms}) do
    mode_str = format_mode(mode)

    """
    connection not available and checkout timed out after #{timeout_ms}ms in #{mode_str} mode. \
    This means requests are coming in and your connection pool cannot serve them fast enough.

    You can address this by:

      1. Ensuring your database is available and that you can connect to it
      2. Tracking down slow queries and making sure they are running fast enough
      3. #{pool_size_hint(mode)}
      4. Increasing the checkout timeout (note: this increases latency under load)

    See #{@docs_url} for more information on connection pooling.\
    """
  end

  @impl Supavisor.Error
  def log_message(%{mode: mode, timeout_ms: timeout_ms} = error) do
    mode_str = format_mode(mode)

    IO.iodata_to_binary([
      ?(,
      error.code,
      ?),
      " checkout timeout after #{timeout_ms}ms in #{mode_str} mode"
    ])
  end

  @impl Supavisor.Error
  def log_level(_), do: :warning

  # Private helpers

  defp format_mode(:session), do: "Session"
  defp format_mode(:transaction), do: "Transaction"
  defp format_mode(mode), do: mode |> to_string() |> String.capitalize()

  defp pool_size_hint(:session) do
    "Increasing the pool_size (note: in Session mode each client holds a dedicated connection, so pool_size directly limits concurrent clients)"
  end

  defp pool_size_hint(:transaction) do
    "Increasing the pool_size (note: this increases database resource consumption, but Transaction mode allows connection reuse between queries)"
  end

  defp pool_size_hint(_mode) do
    "Increasing the pool_size (note: this increases database resource consumption)"
  end
end
