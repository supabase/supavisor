defmodule Supavisor.Integration.RestartNodeTest do
  use SupavisorWeb.ConnCase, async: false

  import ExUnit.CaptureLog
  import Supavisor.Asserts, only: [assert_eventually: 3]

  alias Supavisor.JWT.SharedSecret.Token
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

    assert %{"nodes" => [%{"node" => name}]} = conn |> get(~p"/api/nodes") |> json_response(200)
    assert name == to_string(node())
  end

  test "halts a node whose graceful stop hangs, once the watchdog fires", %{
    peer: peer,
    peer_node: peer_node
  } do
    # A task that ignores the shutdown signal keeps the application from stopping.
    stuck_task =
      defmodule StuckTask do
        def run(test_pid) do
          Process.flag(:trap_exit, true)

          receive do
            {:EXIT, _from, :shutdown} -> send(test_pid, :shutdown_ignored)
          end

          Process.sleep(:infinity)
        end
      end

    :ok = Cluster.load_module(peer, stuck_task)

    {:ok, _task} =
      :peer.call(peer, Task.Supervisor, :start_child, [
        Supavisor.TaskSupervisor,
        StuckTask,
        :run,
        [self()],
        [shutdown: :infinity]
      ])

    :ok = :peer.call(peer, Supavisor.Ops, :restart_node_local, [[delay: 100, watchdog: 1_000]])

    # The graceful stop has started and the task ignores it, so only the watchdog can end the node.
    assert_receive :shutdown_ignored, 2_000

    assert_eventually(10, 1_000, fn -> peer_node not in Node.list() end)
  end

  test "restart_node/1 returns :ambiguous when several nodes share the host", %{
    peer_node: peer_node
  } do
    log =
      capture_log([level: :warning], fn ->
        assert {:error, :ambiguous} = Supavisor.Ops.restart_node("127.0.0.1")
      end)

    assert log =~ "Restart node 127.0.0.1: ambiguous"
    assert peer_node in Node.list()
  end

  test "returns 409 when several nodes share the host", %{conn: conn} do
    assert %{"error" => "several nodes share this host" <> _} =
             conn |> post(~p"/api/nodes/127.0.0.1/restart") |> json_response(409)
  end
end
