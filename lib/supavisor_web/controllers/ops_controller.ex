defmodule SupavisorWeb.OpsController do
  use SupavisorWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias SupavisorWeb.OpenApiSchemas.{Empty, NodeList, NotFound}

  plug OpenApiSpex.Plug.CastAndValidate, json_render_error_v2: true, replace_params: false
  plug :put_view, SupavisorWeb.OpsJSON

  @authorization [
    in: :header,
    name: :authorization,
    schema: %OpenApiSpex.Schema{type: :string},
    required: true,
    example:
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2ODAxNjIxNTR9.U9orU6YYqXAtpF8uAiw6MS553tm4XxRzxOhz2IwDhpY"
  ]

  operation(:index,
    summary: "List the nodes of the cluster",
    description: """
    Lists the nodes connected to the node that receives the request, with their health.
    Nodes that fail to respond are reported under `errors`.
    """,
    parameters: [authorization: @authorization],
    responses: %{200 => NodeList.response()}
  )

  def index(conn, _params) do
    render(conn, :index, result: Supavisor.Ops.list_nodes())
  end

  operation(:restart_node,
    summary: "Restart a node of the cluster",
    description: """
    Restarts a node of the cluster, identified by the host part of its node name or by
    its full node name. It can be any node, not only the one that receives the request.

    `202` only confirms the restart was initiated: the node exits shortly after, and
    whatever supervises the process is expected to start it again.
    """,
    parameters: [
      nodehost: [in: :path, description: "Node host or full node name", type: :string],
      authorization: @authorization
    ],
    responses: %{
      202 => {"Restart initiated", "application/json", Empty},
      404 => NotFound.response(),
      409 => {"Several nodes share the host", "application/json", Empty},
      503 => {"Node unreachable", "application/json", Empty}
    }
  )

  def restart_node(conn, %{"nodehost" => nodehost}) do
    case Supavisor.Ops.restart_node(nodehost) do
      :ok ->
        send_resp(conn, 202, "")

      {:error, :not_found} ->
        conn |> put_status(404) |> render(:error, error: "not found")

      {:error, :ambiguous} ->
        conn
        |> put_status(409)
        |> render(:error, error: "several nodes share this host, use the full node name")

      {:error, :node_unreachable} ->
        conn |> put_status(503) |> render(:error, error: "node unreachable")
    end
  end
end
