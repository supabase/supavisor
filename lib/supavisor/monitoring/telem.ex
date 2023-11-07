defmodule Supavisor.Monitoring.Telem do
  @moduledoc false

  require Logger

  alias Supavisor, as: S

  @spec network_usage(:client | :db, S.sock(), S.id(), map()) :: {:ok | :error, map()}
  def network_usage(type, {mod, socket}, id, stats) do
    mod = if mod == :ssl, do: :ssl, else: :inet

    case mod.getstat(socket) do
      {:ok, values} ->
        values = Map.new(values)
        diff = Map.merge(values, stats, fn _, v1, v2 -> v1 - v2 end)

        {tenant, user, mode} = id

        :telemetry.execute(
          [:supavisor, type, :network, :stat],
          diff,
          %{tenant: tenant, user: user, mode: mode}
        )

        {:ok, values}

      {:error, reason} ->
        Logger.error("Failed to get socket stats: #{inspect(reason)}")
        {:error, stats}
    end
  end

  @spec pool_checkout_time(integer(), S.id()) :: :ok
  def pool_checkout_time(time, {tenant, user, mode}) do
    :telemetry.execute(
      [:supavisor, :pool, :checkout, :stop],
      %{duration: time},
      %{tenant: tenant, user: user, mode: mode}
    )
  end

  @spec client_query_time(integer(), S.id()) :: :ok
  def client_query_time(start, {tenant, user, mode}) do
    :telemetry.execute(
      [:supavisor, :client, :query, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant, user: user, mode: mode}
    )
  end

  @spec client_join(:ok | :fail, S.id()) :: :ok
  def client_join(status, {tenant, user, mode}) do
    :telemetry.execute(
      [:supavisor, :client, :joins, status],
      %{},
      %{tenant: tenant, user: user, mode: mode}
    )
  end
end
