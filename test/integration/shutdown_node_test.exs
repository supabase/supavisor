defmodule Supavisor.Integration.ShutdownNodeTest do
  use SupavisorWeb.ConnCase, async: false

  import ExUnit.CaptureLog
  import Supavisor.Asserts, only: [assert_eventually: 3]

  alias Supavisor.JWT.SharedSecret.Token
  alias Supavisor.Support.Cluster

  @moduletag cluster: true

  setup %{conn: conn} do
    peer_name = :peer.random_name()
    {:ok, peer, peer_node} = Cluster.start_node(peer_name)
    true = Node.connect(peer_node)

    token = Token.gen!(Application.fetch_env!(:supavisor, :api_jwt_secret))

    %{
      conn: put_req_header(conn, "authorization", "Bearer " <> token),
      peer: peer,
      peer_name: peer_name,
      peer_node: peer_node
    }
  end

  test "shuts down another node of the cluster, replying before it exits", %{
    conn: conn,
    peer: peer,
    peer_node: peer_node
  } do
    boot_id = :peer.call(peer, Supavisor.Ops, :boot_id, [])

    assert %{"node" => name, "boot_id" => ^boot_id} =
             conn |> post(~p"/api/nodes/#{peer_node}/shutdown") |> json_response(202)

    assert name == to_string(peer_node)
    # The reply goes out before the node exits.
    assert peer_node in Node.list()

    assert_eventually(15, 1_000, fn -> peer_node not in Node.list() end)

    assert %{"nodes" => [%{"node" => name}]} = conn |> get(~p"/api/nodes") |> json_response(200)
    assert name == to_string(node())
  end

  test "a node started again has another boot id than the one that was shut down", %{
    conn: conn,
    peer_name: peer_name,
    peer_node: peer_node
  } do
    assert %{"boot_id" => old_boot_id} =
             conn |> post(~p"/api/nodes/#{peer_node}/shutdown") |> json_response(202)

    assert_eventually(15, 1_000, fn -> peer_node not in Node.list() end)

    # Peers have no supervisor, so start the node again by hand.
    stop_supervised({:peer, peer_name})
    {:ok, peer, ^peer_node} = Cluster.start_node(peer_name)
    true = Node.connect(peer_node)
    new_boot_id = :peer.call(peer, Supavisor.Ops, :boot_id, [])

    assert new_boot_id != old_boot_id

    assert %{"nodes" => nodes} = conn |> get(~p"/api/nodes") |> json_response(200)
    assert %{"boot_id" => ^new_boot_id} = Enum.find(nodes, &(&1["node"] == to_string(peer_node)))
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

    assert {:ok, _boot_id} =
             :peer.call(peer, Supavisor.Ops, :shutdown_node_local, [[delay: 100, watchdog: 1_000]])

    # The graceful stop has started and the task ignores it, so only the watchdog can end the node.
    assert_receive :shutdown_ignored, 2_000

    assert_eventually(10, 1_000, fn -> peer_node not in Node.list() end)
  end

  test "shutdown_node/1 returns :node_unreachable when the shutdown fails on the node", %{
    peer: peer,
    peer_node: peer_node
  } do
    failing_shutdown =
      defmodule FailingShutdown do
        def run, do: raise("boom")
      end

    :ok = Cluster.load_module(peer, failing_shutdown)
    :ok = :peer.call(peer, :meck, :new, [Supavisor.Ops, [:passthrough, :no_link]])

    :ok =
      :peer.call(peer, :meck, :expect, [
        Supavisor.Ops,
        :shutdown_node_local,
        &FailingShutdown.run/0
      ])

    log =
      capture_log([level: :warning], fn ->
        assert {:error, :node_unreachable} = Supavisor.Ops.shutdown_node(to_string(peer_node))
      end)

    assert log =~
             ~s(Failed to shut down node #{peer_node}: {:badrpc, {:error, {:exception, %RuntimeError{message: "boom"})

    assert peer_node in Node.list()
  end

  test "shutdown_node/1 returns :ambiguous when several nodes share the host", %{
    peer_node: peer_node
  } do
    log =
      capture_log([level: :warning], fn ->
        assert {:error, :ambiguous} = Supavisor.Ops.shutdown_node("127.0.0.1")
      end)

    assert log =~ "Shut down node 127.0.0.1: ambiguous"
    assert peer_node in Node.list()
  end

  test "returns 409 when several nodes share the host", %{conn: conn} do
    assert %{"error" => "several nodes share this host" <> _} =
             conn |> post(~p"/api/nodes/127.0.0.1/shutdown") |> json_response(409)
  end
end
