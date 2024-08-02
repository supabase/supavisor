defmodule Supavisor.Monitoring.Telem do
  @moduledoc false

  require Logger

  @metrics_disabled Application.compile_env(:supavisor, :metrics_disabled, false)

  defmacro telemetry_execute(event_name, measurements, metadata) do
    if not @metrics_disabled do
      quote do
        :telemetry.execute(unquote(event_name), unquote(measurements), unquote(metadata))
      end
    end
  end

  defmacro network_usage_disable(do: block) do
    if @metrics_disabled do
      quote do
        {:ok, %{recv_oct: 0, send_oct: 0}}
      end
    else
      block
    end
  end

  @spec network_usage(:client | :db, Supavisor.sock(), Supavisor.id(), map()) ::
          {:ok | :error, map()}
  def network_usage(type, {mod, socket}, id, _stats) do
    network_usage_disable do
      mod = if mod == :ssl, do: :ssl, else: :inet

      case mod.getstat(socket, [:recv_oct, :send_oct]) do
        {:ok, [{:recv_oct, recv_oct}, {:send_oct, send_oct}]} ->
          stats = %{
            send_oct: send_oct,
            recv_oct: recv_oct
          }

          {{ptype, tenant}, user, mode, db_name} = id

          :telemetry.execute(
            [:supavisor, type, :network, :stat],
            stats,
            %{tenant: tenant, user: user, mode: mode, type: ptype, db_name: db_name}
          )

          {:ok, %{}}

        {:error, reason} ->
          Logger.error("Failed to get socket stats: #{inspect(reason)}")
          {:error, %{}}
      end
    end
  end

  @spec pool_checkout_time(integer(), Supavisor.id(), :local | :remote) :: :ok | nil
  def pool_checkout_time(time, {{type, tenant}, user, mode, db_name}, same_box) do
    telemetry_execute(
      [:supavisor, :pool, :checkout, :stop, same_box],
      %{duration: time},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  @spec client_query_time(integer(), Supavisor.id()) :: :ok | nil
  def client_query_time(start, {{type, tenant}, user, mode, db_name}) do
    telemetry_execute(
      [:supavisor, :client, :query, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  @spec client_connection_time(integer(), Supavisor.id()) :: :ok | nil
  def client_connection_time(start, {{type, tenant}, user, mode, db_name}) do
    telemetry_execute(
      [:supavisor, :client, :connection, :stop],
      %{duration: System.monotonic_time() - start},
      %{tenant: tenant, user: user, mode: mode, type: type, db_name: db_name}
    )
  end

  @spec client_join(:ok | :fail, Supavisor.id() | any()) :: :ok | nil
  def client_join(status, {{type, tenant}, user, mode, db_name}) do
    telemetry_execute(
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
          Supavisor.id()
        ) :: :ok | nil
  def handler_action(handler, action, {{type, tenant}, user, mode, db_name}) do
    telemetry_execute(
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
