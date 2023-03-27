defmodule Supavisor.Monitoring.Telem do
  @moduledoc false

  require Logger

  @spec network_usage(atom(), port(), String.t()) :: :ok
  def network_usage(type, socket, tenant) do
    case :inet.getstat(socket) do
      {:ok, values} ->
        :telemetry.execute(
          [:supavisor, type, :network, :stat],
          Map.new(values),
          %{tenant: tenant}
        )

      {:error, reason} ->
        Logger.error("Failed to get socket stats: #{inspect(reason)}")
    end
  end

  @spec pool_checkout_time(integer(), String.t()) :: :ok
  def pool_checkout_time(time, tenant) do
    :telemetry.execute(
      [:supavisor, :pool, :checkout, :stop],
      %{duration: time},
      %{tenant: tenant}
    )
  end

  @spec client_query_time(integer(), String.t()) :: :ok
  def client_query_time(start, tenant) do
    :telemetry.execute(
      [:supavisor, :client, :query, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant}
    )
  end
end
