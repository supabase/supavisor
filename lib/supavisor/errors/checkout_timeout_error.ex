defmodule Supavisor.Errors.CheckoutTimeoutError do
  @moduledoc """
  This error is returned when unable to check out a connection from the pool due to timeout.
  This happens when all connections in the pool are busy and none become available within the checkout timeout period.
  Applies to both session and transaction modes.

  `reason` says which wait timed out: `:pool_exhausted` (no pooled connection became free,
  usually the tenant's own load) or `:unresponsive` (a connection was picked but its
  DbHandler did not answer).
  """

  use Supavisor.Error, [:mode, :timeout_ms, :reason, code: "ECHECKOUTTIMEOUT"]

  @type t() :: %__MODULE__{
          mode: :session | :transaction,
          timeout_ms: non_neg_integer(),
          reason: :pool_exhausted | :unresponsive | nil,
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{mode: mode, timeout_ms: timeout_ms}) do
    mode_str = mode |> to_string() |> String.capitalize()
    "unable to check out connection from the pool after #{timeout_ms}ms in #{mode_str} mode"
  end

  @impl Supavisor.Error
  def fault(%{reason: :pool_exhausted}), do: :user_limit
  def fault(_), do: :supavisor
end
