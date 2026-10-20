defmodule SupavisorWeb.PoolController do
  use SupavisorWeb, :controller
  use OpenApiSpex.ControllerSpecs

  require Logger

  alias SupavisorWeb.OpenApiSchemas.{
    Empty,
    NotFound,
    PoolList,
    Rebalance,
    RebalanceParams,
    StopPoolParams,
    UnprocessablyEntity
  }

  alias SupavisorWeb.PoolPid

  plug OpenApiSpex.Plug.CastAndValidate, json_render_error_v2: true, replace_params: false
  plug :put_view, SupavisorWeb.PoolJSON

  @authorization [
    in: :header,
    name: :authorization,
    schema: %OpenApiSpex.Schema{type: :string},
    required: true,
    example:
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2ODAxNjIxNTR9.U9orU6YYqXAtpF8uAiw6MS553tm4XxRzxOhz2IwDhpY"
  ]

  operation(:index,
    summary: "List a tenant's pools across the cluster",
    description: """
    `pid` is an opaque handle of the pool's supervisor, used to target the pool in
    other requests. A `shutting_down` pool is draining its clients; a new pool for the
    same id may already be `active` on another node. Nodes that fail to respond are
    reported under `errors`.
    """,
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    responses: %{
      200 => PoolList.response(),
      404 => NotFound.response()
    }
  )

  def index(conn, %{"external_id" => external_id}) do
    case Supavisor.Ops.list_pools(external_id) do
      {:ok, result} ->
        render(conn, :index, result: result)

      {:error, :tenant_not_found} ->
        conn |> put_status(404) |> render(:error, error: "not found")
    end
  end

  operation(:rebalance,
    summary: "Rebalance pools across the cluster",
    description: """
    Moves every pool to the node it would be started on now.

    Pools stay on the node they started on, so pools started while only part of the
    cluster was up are concentrated on the first nodes. The clients of a moved pool
    are disconnected, and start the pool on its new node when they reconnect.

    Pools are stopped in the background. The response lists the pools being moved.
    """,
    parameters: [authorization: @authorization],
    request_body: RebalanceParams.params(),
    responses: %{
      200 => Rebalance.response(),
      422 => UnprocessablyEntity.response()
    }
  )

  operation(:stop,
    summary: "Stop one of a tenant's pools",
    description: """
    Stops the pool identified by `pid` (from the pool list), on whichever node
    runs it. A `pid` of a pool that no longer runs, or of another tenant's pool, is
    not found.

    The pool shuts down gracefully. The request waits up to `timeout` ms for it:
    `204` if the pool stopped in time, `202` if it is still shutting down (it
    completes in the background).
    """,
    parameters: [
      external_id: [in: :path, description: "External id", type: :string],
      authorization: @authorization
    ],
    request_body: StopPoolParams.params(),
    responses: %{
      202 => {"Pool still shutting down", "application/json", Empty},
      204 => Empty.response(),
      404 => NotFound.response(),
      422 => UnprocessablyEntity.response(),
      503 => {"Node of the pool unreachable", "application/json", Empty}
    }
  )

  def stop(conn, %{"external_id" => external_id}) do
    # `timeout` is always set: CastAndValidate fills in the schema default.
    params = conn.private.open_api_spex.body_params

    with {:ok, sup} <- PoolPid.decode(params.pid),
         {:ok, result} <- Supavisor.Ops.stop_pool(external_id, sup, params.timeout) do
      send_resp(conn, if(result == :stopped, do: 204, else: 202), "")
    else
      :error ->
        conn |> put_status(422) |> render(:error, error: "invalid pid")

      {:error, :not_found} ->
        conn |> put_status(404) |> render(:error, error: "not found")

      {:error, :node_unreachable} ->
        conn |> put_status(503) |> render(:error, error: "node unreachable")
    end
  end

  def rebalance(conn, _params) do
    opts =
      for {key, value} <-
            Map.take(conn.private.open_api_spex.body_params, [:dry_run, :max_concurrency]),
          value != nil,
          do: {key, value}

    Logger.warning("Rebalancing pools: #{inspect(opts)}")

    render(conn, :rebalance, result: Supavisor.rebalance(opts))
  end
end
