defmodule Supavisor.Errors.CircuitBreakerError do
  @moduledoc """
  This error is returned when the circuit breaker is open for a particular operation
  """

  use Supavisor.Error, [:operation, :blocked_until, code: "ECIRCUITBREAKER"]

  @type t() :: %__MODULE__{
          operation: atom(),
          blocked_until: term(),
          code: binary()
        }

  @impl Supavisor.Error
  def error_message(%{operation: operation}) do
    explanation = Supavisor.CircuitBreaker.explanation(operation)
    "circuit breaker open: #{explanation}"
  end

  @impl Supavisor.Error
  def log_message(%{operation: operation, blocked_until: blocked_until}) do
    "Circuit breaker open for operation: #{operation}, blocked until: #{blocked_until}"
  end
end
