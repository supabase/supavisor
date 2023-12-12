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

        {{ptype, tenant}, user, mode} = id

        :telemetry.execute(
          [:supavisor, type, :network, :stat],
          diff,
          %{tenant: tenant, user: user, mode: mode, type: ptype}
        )

        {:ok, values}

      {:error, reason} ->
        Logger.error("Failed to get socket stats: #{inspect(reason)}")
        {:error, stats}
    end
  end

  @spec pool_checkout_time(integer(), S.id()) :: :ok
  def pool_checkout_time(time, {{type, tenant}, user, mode}) do
    :telemetry.execute(
      [:supavisor, :pool, :checkout, :stop],
      %{duration: time},
      %{tenant: tenant, user: user, mode: mode, type: type}
    )
  end

  @spec client_query_time(integer(), S.id()) :: :ok
  def client_query_time(start, {{type, tenant}, user, mode}) do
    :telemetry.execute(
      [:supavisor, :client, :query, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant, user: user, mode: mode, type: type}
    )
  end

  @spec client_join(:ok | :fail, S.id() | any()) :: :ok
  def client_join(_status, {tenant, user, mode}) do
    :telemetry.execute(
      [:supavisor, :client, :joins, status],
      %{},
      %{tenant: tenant, user: user, mode: mode}
    )
  end

  def client_join(status, id) do
    Logger.warning("client_join is called with a mismatched id: #{inspect(id)}")
  end
end
