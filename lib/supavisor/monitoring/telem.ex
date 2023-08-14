defmodule Supavisor.Monitoring.Telem do
  @moduledoc false

  require Logger

  @spec network_usage(
          atom(),
          {:gen_tcp, :gen_tcp.socket()} | {:ssl, :ssl.socket()},
          String.t(),
          String.t(),
          map()
        ) :: {:ok | :error, map()}
  def network_usage(type, {mod, socket}, tenant, user_alias, stats) do
    mod = if mod == :ssl, do: :ssl, else: :inet

    case mod.getstat(socket) do
      {:ok, values} ->
        values = Map.new(values)
        diff = Map.merge(values, stats, fn _, v1, v2 -> v1 - v2 end)

        :telemetry.execute(
          [:supavisor, type, :network, :stat],
          diff,
          %{tenant: tenant, user_alias: user_alias}
        )

        {:ok, values}

      {:error, reason} ->
        Logger.error("Failed to get socket stats: #{inspect(reason)}")
        {:error, stats}
    end
  end

  @spec pool_checkout_time(integer(), String.t(), String.t()) :: :ok
  def pool_checkout_time(time, tenant, user_alias) do
    :telemetry.execute(
      [:supavisor, :pool, :checkout, :stop],
      %{duration: time},
      %{tenant: tenant, user_alias: user_alias}
    )
  end

  @spec client_query_time(integer(), String.t(), String.t()) :: :ok
  def client_query_time(start, tenant, user_alias) do
    :telemetry.execute(
      [:supavisor, :client, :query, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant, user_alias: user_alias}
    )
  end
end
