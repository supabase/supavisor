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

        {{ptype, tenant}, user, mode, db_name} = id

        :telemetry.execute(
          [:supavisor, type, :network, :stat],
          diff,
          %{tenant: tenant, user: user, mode: mode, type: ptype, db_name: db_name}
        )

        {:ok, values}

      {:error, reason} ->
        Logger.error("Failed to get socket stats: #{inspect(reason)}")
        {:error, stats}
    end
  end

  @spec pool_checkout_time(integer(), S.id(), :local | :remote) :: :ok
  def pool_checkout_time(time, {{type, tenant}, user, mode, db_name}, same_box) do
    :telemetry.execute(
      [:supavisor, :pool, :checkout, :stop, same_box],
      %{duration: time},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  @spec client_query_time(integer(), S.id()) :: :ok
  def client_query_time(start, {{type, tenant}, user, mode, db_name}) do
    :telemetry.execute(
      [:supavisor, :client, :query, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  @spec client_connection_time(integer(), S.id()) :: :ok
  def client_connection_time(start, {{type, tenant}, user, mode, db_name}) do
    :telemetry.execute(
      [:supavisor, :client, :connection, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  @spec client_join(:ok | :fail, S.id() | any()) :: :ok
  def client_join(status, {{type, tenant}, user, mode, db_name}) do
    :telemetry.execute(
      [:supavisor, :client, :joins, status],
      %{},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  def client_join(_status, id) do
    Logger.warning("client_join is called with a mismatched id: #{inspect(id)}")
  end

  @spec handler_action(
          :client_handler | :db_handler,
          :started | :stopped | :db_connection,
          S.id()
        ) :: :ok
  def handler_action(handler, action, {{type, tenant}, user, mode, db_name}) do
    :telemetry.execute(
      [:supavisor, handler, action, :all],
      %{},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  def handler_action(handler, action, id) do
    Logger.warning(
      "handler_action is called with a mismatched #{inspect(handler)} #{inspect(action)} #{inspect(id)}"
    )
  end
end
