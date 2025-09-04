defmodule Supavisor.ConnectionRateLimiter do
  @moduledoc """
  Rate limiting for client connections using Hammer.
  """

  use Hammer, backend: :ets

  require Logger

  def child_spec(_opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [[clean_period: :timer.minutes(1)]]},
      type: :worker,
      restart: :permanent,
      shutdown: 5000
    }
  end

  @doc """
  Check rate limit and handle response based on configuration.
  Skips rate limiting for local connections.
  """
  @spec check_rate_limit(String.t(), boolean()) :: :ok | :deny
  def check_rate_limit(_peer_ip, true = _local) do
    :ok
  end

  def check_rate_limit(peer_ip, false = _local) do
    config = config()

    case hit("connection:#{peer_ip}", config[:interval], config[:max_hits]) do
      {:allow, _count} ->
        :ok

      {:deny, _retry_after_ms} ->
        if config[:enforce?] do
          Logger.warning("ConnectionRateLimiter: Denying connection for IP #{peer_ip}")
          :deny
        else
          Logger.warning(
            "ConnectionRateLimiter: Rate limit exceeded but enforcement disabled, allowing connection for IP #{peer_ip}"
          )

          :ok
        end
    end
  end

  defp config do
    Application.get_env(:supavisor, __MODULE__)
  end
end
