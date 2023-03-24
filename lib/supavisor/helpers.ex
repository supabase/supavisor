defmodule Supavisor.Helpers do
  @moduledoc """
  This module includes helper functions for different contexts that can't be union in one module.
  """
  require Logger

  @spec log_network_usage(atom(), port(), string()) :: :ok
  def log_network_usage(type, socket, tenant) do
    case :inet.getstat(socket) do
      {ok, values} ->
        :telemetry.execute(
          [:supavisor, type, :network, :stat],
          Map.new(values),
          %{tenant: tenant}
        )

      {:error, reason} ->
        Logger.error("Failed to get socket stats: #{inspect(reason)}")
    end
  end
end
