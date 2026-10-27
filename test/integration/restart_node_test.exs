defmodule Supavisor.Integration.RestartNodeTest do
  use SupavisorWeb.ConnCase, async: false

  import Supavisor.Asserts, only: [assert_eventually: 3]

  alias Supavisor.Jwt.Token
  alias Supavisor.Support.Cluster

  @moduletag cluster: true

  setup %{conn: conn} do
    {:ok, peer, peer_node} = Cluster.start_node()
    true = Node.connect(peer_node)

    token = Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))

    %{
      conn: put_req_header(conn, "authorization", "Bearer " <> token),
      peer: peer,
      peer_node: peer_node
    }
  end

  test "restarts another node of the cluster, replying before it exits", %{
    conn: conn,
    peer_node: peer_node
  } do
    assert conn |> post(~p"/api/nodes/#{peer_node}/restart") |> response(202)
    # The reply goes out before the node exits.
    assert peer_node in Node.list()

    assert_eventually(15, 1_000, fn -> peer_node not in Node.list() end)
  end

  test "halts a node whose graceful stop hangs, once the watchdog fires", %{
    peer: peer,
    peer_node: peer_node
  } do
    # A task that ignores the shutdown signal keeps the application from stopping. It is
    # started from source because the peer can't load a fun defined in this test.
    stuck_task = """
    Task.Supervisor.start_child(
      Supavisor.TaskSupervisor,
      fn ->
        Process.flag(:trap_exit, true)
        Process.sleep(:infinity)
      end,
      shutdown: :infinity
    )
    """

    {{:ok, _task}, _binding} = :peer.call(peer, Code, :eval_string, [stuck_task])

    :ok = :peer.call(peer, Supavisor.Ops, :restart_node_local, [[delay: 100, watchdog: 1_000]])

    assert_eventually(10, 1_000, fn -> peer_node not in Node.list() end)
  end

  test "returns 409 when several nodes share the host", %{conn: conn} do
    assert %{"error" => "several nodes share this host" <> _} =
             conn |> post(~p"/api/nodes/127.0.0.1/restart") |> json_response(409)
  end

  test "returns 404 for a node that is not in the cluster", %{conn: conn} do
    assert %{"error" => "not found"} =
             conn |> post(~p"/api/nodes/no_such_node/restart") |> json_response(404)
  end
end
