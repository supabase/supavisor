defmodule Supavisor.HttpSql.Telemetry do
  @moduledoc """
  Thin telemetry wrappers for HTTP /sql events. Centralizes event names so the
  controller, plug, and PromEx plugin agree.

  Events:

    * `[:supavisor, :http_sql, :request, :start | :stop | :exception]`
      Wraps a single HTTP /sql controller action. `:stop` measurements
      `%{duration, query_size_bytes, response_rows, response_bytes}` with
      metadata `%{tenant, user, status_code, batch_size, mode}`.

    * `[:supavisor, :http_sql, :pool, :checkout]`
      Latency of `start_dist + subscribe + poolboy.checkout + DbHandler.checkout`
      for one query. `%{duration: us}` with `%{tenant, user, hit?: :hit | :miss}`.
      `hit?` is informational only — the new path does not maintain a separate
      cache layer, so the value is always `:hit` for now and will become
      meaningful again if a pre-checkout cache is introduced.

    * `[:supavisor, :http_sql, :max_clients_rejected]`
      Emitted when `Supavisor.subscribe/2` returns `MaxConnectionsError`. Lets
      operators alert on tenant-level saturation before users notice.
      `%{count: 1}` with `%{tenant, user, limit_kind: :max_clients | :pool_size}`.
  """

  alias Supavisor.Errors.MaxConnectionsError

  @doc """
  Wrap the body of a controller action in a `:telemetry.span` covering the
  `:request` events. The body must return `{:ok, response}` or
  `{:error, term}`; the result is forwarded to the caller and the
  status/size are added to metadata for the `:stop` event.
  """
  @spec request_span(map, (-> {:ok, map} | {:error, term})) ::
          {:ok, map} | {:error, term}
  def request_span(base_metadata, fun) when is_map(base_metadata) and is_function(fun, 0) do
    :telemetry.span(
      [:supavisor, :http_sql, :request],
      base_metadata,
      fn ->
        result = fun.()
        meta = Map.merge(base_metadata, result_metadata(result))
        {result, meta}
      end
    )
  end

  @doc """
  Emit a `:pool, :checkout` event with the latency and hit/miss tag.
  """
  @spec pool_checkout(integer, :hit | :miss, map) :: :ok
  def pool_checkout(duration_us, hit_or_miss, metadata) do
    :telemetry.execute(
      [:supavisor, :http_sql, :pool, :checkout],
      %{duration: duration_us},
      Map.put(metadata, :hit?, hit_or_miss)
    )
  end

  @doc """
  Emit a `:max_clients_rejected` event when the tenant's per-pool subscriber
  cap is hit. Operators can alert on the rate of this counter to spot tenants
  that need a raised `max_clients` config.
  """
  @spec max_clients_rejected(map, atom) :: :ok
  def max_clients_rejected(metadata, limit_kind \\ :max_clients) when is_map(metadata) do
    :telemetry.execute(
      [:supavisor, :http_sql, :max_clients_rejected],
      %{count: 1},
      Map.put(metadata, :limit_kind, limit_kind)
    )
  end

  # ---------------------------------------------------------------------------

  # The facade returns the Neon-shape body straight from
  # `ResponseBuilder.build_single/2` or `build_batch/2`, which uses
  # string keys (`"rowCount"`, `"rows"`, `"results"`). Read those.
  defp result_metadata({:ok, %{"results" => list}}) when is_list(list) do
    rows = Enum.reduce(list, 0, fn r, acc -> acc + Map.get(r, "rowCount", 0) end)
    %{status_code: 200, response_rows: rows}
  end

  defp result_metadata({:ok, %{"rowCount" => n}}) when is_integer(n) do
    %{status_code: 200, response_rows: n}
  end

  defp result_metadata({:ok, _resp}), do: %{status_code: 200, response_rows: 0}

  defp result_metadata({:error, %MaxConnectionsError{}}),
    do: %{status_code: 429, response_rows: 0}

  defp result_metadata({:error, _}), do: %{status_code: 500, response_rows: 0}
end
