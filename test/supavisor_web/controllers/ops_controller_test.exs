defmodule SupavisorWeb.OpsControllerTest do
  use SupavisorWeb.ConnCase, async: false

  alias Supavisor.JWT.SharedSecret.Token

  describe "GET /api/nodes" do
    setup %{conn: conn} do
      {:ok, conn: put_req_header(conn, "authorization", "Bearer " <> gen_token())}
    end

    test "lists this node with its uptime, version and health", %{conn: conn} do
      name = to_string(node())

      assert %{nodes: [info], errors: errors} =
               conn |> get(~p"/api/nodes") |> json_response(200) |> assert_schema("NodeList")

      assert errors == %{}

      assert %{node: ^name, host: host, uptime_ms: uptime_ms, version: version} = info
      assert [_name, ^host] = String.split(name, "@")
      assert is_integer(uptime_ms)
      assert version == to_string(Application.spec(:supavisor, :vsn))
      assert info.health == %{status: "healthy", failed_checks: []}
    end

    test "renders failed checks and unreachable nodes", %{conn: conn} do
      info = %{
        node: :"supavisor@10.0.0.1",
        host: "10.0.0.1",
        uptime_ms: 1_000,
        version: "1.0.0",
        health: {:error, :failed_checks, [:database_reachable]}
      }

      stub_ops(:list_nodes, fn ->
        %{nodes: [info], errors: %{"supavisor@10.0.0.2": :timeout}}
      end)

      body = conn |> get(~p"/api/nodes") |> json_response(200)
      assert_schema(body, "NodeList")

      assert body == %{
               "nodes" => [
                 %{
                   "node" => "supavisor@10.0.0.1",
                   "host" => "10.0.0.1",
                   "uptime_ms" => 1_000,
                   "version" => "1.0.0",
                   "health" => %{
                     "status" => "unhealthy",
                     "failed_checks" => ["database_reachable"]
                   }
                 }
               ],
               "errors" => %{"supavisor@10.0.0.2" => "unreachable"}
             }
    end

    test "requires authorization" do
      assert build_conn() |> get(~p"/api/nodes") |> response(403)
    end

    test "is documented in the OpenAPI spec", %{conn: conn} do
      spec = conn |> get(~p"/api/openapi") |> json_response(200)
      assert %{"responses" => %{"200" => _}} = spec["paths"]["/api/nodes"]["get"]
    end
  end

  describe "POST /api/nodes/:nodehost/restart" do
    setup %{conn: conn} do
      {:ok, conn: put_req_header(conn, "authorization", "Bearer " <> gen_token())}
    end

    test "returns 404 for a node that is not in the cluster", %{conn: conn} do
      assert %{"error" => "not found"} =
               conn
               |> post(~p"/api/nodes/no_such_node/restart")
               |> json_response(404)
    end

    test "returns 202 for hosts and full node names, with an IP or a domain", %{conn: conn} do
      stub_restart_node(:ok)

      targets = [
        "10.0.0.5",
        "supavisor@10.0.0.5",
        "ip-10-0-0-5.ec2.internal",
        "supavisor@ip-10-0-0-5.ec2.internal"
      ]

      for target <- targets do
        assert conn |> post(~p"/api/nodes/#{target}/restart") |> response(202) == ""
        assert :meck.called(Supavisor.Ops, :restart_node, [target])
      end
    end

    test "returns 409 when several nodes share the host", %{conn: conn} do
      stub_restart_node({:error, :ambiguous})

      assert %{"error" => "several nodes share this host" <> _} =
               conn
               |> post(~p"/api/nodes/127.0.0.1/restart")
               |> json_response(409)
    end

    test "returns 503 when the node is unreachable", %{conn: conn} do
      stub_restart_node({:error, :node_unreachable})

      assert %{"error" => "node unreachable"} =
               conn
               |> post(~p"/api/nodes/node1/restart")
               |> json_response(503)
    end

    test "requires authorization" do
      assert build_conn() |> post(~p"/api/nodes/node1/restart") |> response(403)
    end

    test "is documented in the OpenAPI spec", %{conn: conn} do
      spec = conn |> get(~p"/api/openapi") |> json_response(200)

      assert %{"responses" => %{"202" => _, "404" => _, "409" => _, "503" => _}} =
               spec["paths"]["/api/nodes/{nodehost}/restart"]["post"]
    end
  end

  defp stub_restart_node(result) do
    stub_ops(:restart_node, fn _target -> result end)
  end

  defp stub_ops(function, fun) do
    :meck.new(Supavisor.Ops, [:passthrough, :no_link])
    on_exit(fn -> :meck.unload(Supavisor.Ops) end)
    :meck.expect(Supavisor.Ops, function, fun)
  end

  defp gen_token do
    Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))
  end
end
