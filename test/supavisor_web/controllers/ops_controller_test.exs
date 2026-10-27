defmodule SupavisorWeb.OpsControllerTest do
  use SupavisorWeb.ConnCase, async: false

  alias Supavisor.Jwt.Token

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
    :meck.new(Supavisor.Ops, [:passthrough, :no_link])
    on_exit(fn -> :meck.unload(Supavisor.Ops) end)
    :meck.expect(Supavisor.Ops, :restart_node, fn _target -> result end)
  end

  defp gen_token do
    Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))
  end
end
