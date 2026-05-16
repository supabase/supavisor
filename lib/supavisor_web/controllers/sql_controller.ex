defmodule SupavisorWeb.SqlController do
  @moduledoc """
  HTTP /sql controller. Reads the JSON request body, dispatches to the
  HttpSql facade (single or batch), and writes a Neon-shaped JSON
  response. All telemetry, auth, and tenant-resolution work has already
  been performed by `SupavisorWeb.Plugs.NeonAuth`.
  """

  use Phoenix.Controller, namespace: SupavisorWeb

  alias Supavisor.HttpSql
  alias Supavisor.HttpSql.{ErrorMapper, Telemetry, Transaction}

  @spec execute(Plug.Conn.t(), map) :: Plug.Conn.t()
  def execute(conn, params) do
    ctx = conn.assigns.http_sql_ctx
    array_mode = array_mode?(conn)

    Telemetry.request_span(
      %{
        tenant: ctx.tenant_external_id,
        user: ctx.user,
        mode: mode(params),
        # Bucket the raw batch length so PromEx cardinality stays bounded.
        batch_size: batch_size_bucket(batch_size(params))
      },
      fn -> dispatch(ctx, conn, params, array_mode) end
    )
    |> render_result(conn)
  end

  # ---------------------------------------------------------------------------

  defp dispatch(ctx, _conn, %{"query" => sql} = body, array_mode)
       when is_binary(sql) do
    params = Map.get(body, "params") || []
    HttpSql.execute(ctx, sql, params, %{array_mode: array_mode})
  end

  defp dispatch(ctx, conn, %{"queries" => queries}, array_mode) when is_list(queries) do
    batch_opts = Transaction.from_headers(conn.req_headers)

    queries =
      Enum.map(queries, fn q ->
        %{sql: Map.get(q, "query", ""), params: Map.get(q, "params") || []}
      end)

    HttpSql.execute_batch(ctx, queries, batch_opts, %{array_mode: array_mode})
  end

  defp dispatch(_ctx, _conn, _other, _array_mode) do
    {:error,
     {:malformed_request, "body must contain either 'query'+'params' or 'queries'"}}
  end

  defp render_result({:ok, body}, conn) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(200, Jason.encode!(body))
  end

  defp render_result({:error, term}, conn) do
    {status, body} = ErrorMapper.to_neon_error(term)

    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp array_mode?(conn) do
    case get_req_header(conn, "neon-array-mode") do
      ["true" | _] -> true
      _ -> false
    end
  end

  defp mode(%{"queries" => _}), do: :batch
  defp mode(_), do: :single

  defp batch_size(%{"queries" => q}) when is_list(q), do: length(q)
  defp batch_size(_), do: 1

  # Static bucket labels keep PromEx label cardinality bounded.
  defp batch_size_bucket(n) when n <= 1, do: "1"
  defp batch_size_bucket(n) when n <= 10, do: "2-10"
  defp batch_size_bucket(n) when n <= 100, do: "11-100"
  defp batch_size_bucket(n) when n <= 1000, do: "101-1000"
  defp batch_size_bucket(_), do: "1000+"
end
