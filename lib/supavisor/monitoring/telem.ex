defmodule Supavisor.Monitoring.Telem do
  @moduledoc false

  require Logger
  require Supavisor

  alias Supavisor.Errors.AuthQueryError

  @disabled Application.compile_env(:supavisor, :metrics_disabled, false)
  @slow_auth_query_ms 1_000

  if @disabled do
    defp telemetry_execute(_name, _measurements, _meta), do: :ok
  else
    defp telemetry_execute(event_name, measurements, metadata) do
      :telemetry.execute(event_name, measurements, metadata)
    end
  end

  @spec network_usage(:client | :db, Supavisor.sock(), Supavisor.id(), map()) ::
          {:ok | :error, map()}
  if @disabled do
    def network_usage(_type, _sock, _id, _stats), do: {:ok, %{recv_oct: 0, send_oct: 0}}
  else
    def network_usage(type, {mod, socket}, Supavisor.id() = id, stats) do
      mod = if mod == :ssl, do: :ssl, else: :inet

      case mod.getstat(socket, [:recv_oct, :send_oct]) do
        {:ok, [{:recv_oct, recv_oct}, {:send_oct, send_oct}]} ->
          stats = %{
            send_oct: send_oct - Map.get(stats, :send_oct, 0),
            recv_oct: recv_oct - Map.get(stats, :recv_oct, 0)
          }

          :telemetry.execute(
            [:supavisor, type, :network, :stat],
            stats,
            id_to_tags(id)
          )

          {:ok, %{recv_oct: recv_oct, send_oct: send_oct}}

        {:error, reason} ->
          Logger.error("Failed to get socket stats: #{inspect(reason)}")
          {:error, stats}
      end
    end
  end

  @spec pool_checkout_time(integer(), Supavisor.id(), :local | :remote) :: :ok | nil
  def pool_checkout_time(time, Supavisor.id() = id, same_box) do
    if time > 1_000_000 do
      Logger.warning(
        "Pool checkout took over 1s (#{div(time, 1_000)}ms), consider increasing pool size or checking for slow queries"
      )
    end

    telemetry_execute(
      [:supavisor, :pool, :checkout, :stop, same_box],
      %{duration: time},
      id_to_tags(id)
    )
  end

  @spec client_query_time(integer(), Supavisor.id(), boolean()) :: :ok | nil
  def client_query_time(start, Supavisor.id() = id, proxy) do
    telemetry_execute(
      [:supavisor, :client, :query, :stop],
      %{duration: System.monotonic_time() - start},
      Map.put(id_to_tags(id), :proxy, proxy)
    )
  end

  @spec client_connection_time(integer(), Supavisor.id()) :: :ok | nil
  def client_connection_time(start, Supavisor.id() = id) do
    telemetry_execute(
      [:supavisor, :client, :connection, :stop],
      %{duration: System.monotonic_time() - start},
      id_to_tags(id)
    )
  end

  @spec client_join(:ok | :fail, Supavisor.id() | any()) :: :ok | nil
  def client_join(status, Supavisor.id() = id) do
    telemetry_execute(
      [:supavisor, :client, :joins, status],
      %{},
      id_to_tags(id)
    )
  end

  def client_join(_status, id) do
    Logger.debug("client_join is called with a mismatched id: #{Supavisor.inspect_id(id)}")
  end

  @spec handler_action(
          :client_handler | :db_handler,
          :started | :stopped | :db_connection,
          Supavisor.id()
        ) :: :ok | nil
  def handler_action(handler, action, Supavisor.id() = id) do
    telemetry_execute(
      [:supavisor, handler, action, :all],
      %{},
      id_to_tags(id)
    )
  end

  def handler_action(handler, action, id) do
    Logger.debug(
      "handler_action is called with a mismatched #{inspect(handler)} #{inspect(action)} #{inspect(id)}"
    )
  end

  def prepared_statements_evicted(count, Supavisor.id() = id) do
    telemetry_execute(
      [:supavisor, :db_handler, :prepared_statements, :evicted],
      %{count: count},
      id_to_tags(id)
    )
  end

  @spec auth_query_connection_stop(integer(), {:ok, any()} | {:error, AuthQueryError.t()}) ::
          :ok | nil
  def auth_query_connection_stop(duration, result) do
    {result_tag, reason_tag} = classify_auth_query_result(result)

    telemetry_execute(
      [:supavisor, :auth_query, :connection, :stop],
      %{duration: duration},
      %{result: result_tag, reason: reason_tag}
    )
  end

  @spec auth_query_query_stop(integer(), {:ok, any()} | {:error, AuthQueryError.t()}) :: :ok | nil
  def auth_query_query_stop(duration, result) do
    duration_ms = System.convert_time_unit(duration, :native, :millisecond)

    if duration_ms > @slow_auth_query_ms do
      Logger.warning("auth_query took over #{@slow_auth_query_ms}ms (#{duration_ms}ms)")
    end

    {result_tag, reason_tag} = classify_auth_query_result(result)

    telemetry_execute(
      [:supavisor, :auth_query, :query, :stop],
      %{duration: duration},
      %{result: result_tag, reason: reason_tag}
    )
  end

  @spec get_secrets_stop(integer(), {:ok, any()} | {:error, any()}, :local | :remote) :: :ok | nil
  def get_secrets_stop(duration, result, locality) when locality in [:local, :remote] do
    {result_tag, reason_tag} =
      case result do
        {:error, :not_started} -> {:error, :not_started}
        {:error, :no_auth_config} -> {:error, :no_auth_config}
        other -> classify_auth_query_result(other)
      end

    telemetry_execute(
      [:supavisor, :secret_checker, :get_secrets, :stop, locality],
      %{duration: duration},
      %{result: result_tag, reason: reason_tag}
    )
  end

  @spec update_credentials_stop(integer(), :ok | {:error, any()}, :local | :remote) :: :ok | nil
  def update_credentials_stop(duration, result, locality) when locality in [:local, :remote] do
    {result_tag, reason_tag} =
      case result do
        :ok -> {:ok, :ok}
        {:error, :not_started} -> {:error, :not_started}
        {:error, _} -> {:error, :unknown}
      end

    telemetry_execute(
      [:supavisor, :secret_checker, :update_credentials, :stop, locality],
      %{duration: duration},
      %{result: result_tag, reason: reason_tag}
    )
  end

  @spec id_to_tags(Supavisor.id()) :: map()
  defp id_to_tags(
         Supavisor.id(
           type: type,
           tenant: tenant,
           user: user,
           mode: mode,
           db: db_name,
           search_path: search_path
         )
       ) do
    %{
      type: type,
      tenant: tenant,
      user: user,
      mode: mode,
      db_name: db_name,
      search_path: search_path
    }
  end

  defp classify_auth_query_result(:ok), do: {:ok, :ok}
  defp classify_auth_query_result({:ok, _}), do: {:ok, :ok}
  defp classify_auth_query_result({:error, %AuthQueryError{reason: r}}), do: {:error, r}
  defp classify_auth_query_result({:error, _}), do: {:error, :unknown}
end
