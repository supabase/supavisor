defmodule Supavisor.Integration.ListNodesTest do
  use Supavisor.DataCase, async: false

  import ExUnit.CaptureLog

  alias Supavisor.Ops
  alias Supavisor.Support.Cluster

  @moduletag cluster: true

  setup do
    {:ok, peer, peer_node} = Cluster.start_node()
    true = Node.connect(peer_node)
    %{peer: peer, peer_node: peer_node}
  end

  test "list_nodes/0 lists every node of the cluster, sorted by name", %{peer_node: peer_node} do
    assert %{nodes: nodes, errors: errors} = Ops.list_nodes()
    assert errors == %{}
    assert Enum.map(nodes, & &1.node) == Enum.sort([node(), peer_node])

    by_node = Map.new(nodes, &{&1.node, &1})
    assert_node_info(by_node[node()], node(), :ok)
    assert_node_info(by_node[peer_node], peer_node, :ok)

    # The peer started after this node.
    assert by_node[peer_node].uptime_ms < by_node[node()].uptime_ms
  end

  test "list_nodes/0 reports a node whose health check hangs as unhealthy", %{
    peer: peer,
    peer_node: peer_node
  } do
    hanging_check =
      defmodule HangingCheck do
        def run, do: Process.sleep(:infinity)
      end

    :ok = Cluster.load_module(peer, hanging_check)
    :ok = :peer.call(peer, :meck, :new, [Supavisor.Health, [:passthrough, :no_link]])

    :ok =
      :peer.call(peer, :meck, :expect, [
        Supavisor.Health,
        :database_reachable?,
        &HangingCheck.run/0
      ])

    assert %{nodes: nodes, errors: errors} = Ops.list_nodes()
    assert errors == %{}

    by_node = Map.new(nodes, &{&1.node, &1})
    assert Map.keys(by_node) |> Enum.sort() == Enum.sort([node(), peer_node])
    assert_node_info(by_node[node()], node(), :ok)

    assert_node_info(
      by_node[peer_node],
      peer_node,
      {:error, :failed_checks, [:database_reachable]}
    )
  end

  test "list_nodes/0 reports a node that fails to answer under errors", %{peer_node: peer_node} do
    :meck.new(Ops, [:passthrough, :no_link])
    on_exit(fn -> :meck.unload(Ops) end)
    :meck.expect(Ops, :node_info_local, fn -> raise "boom" end)

    # The stub is on this node only, so the peer still answers.
    log =
      capture_log([level: :warning], fn ->
        assert %{nodes: [%{node: ^peer_node}], errors: errors} = Ops.list_nodes()
        local = node()
        assert %{^local => {:error, {:exception, %RuntimeError{message: "boom"}, _}}} = errors
        assert map_size(errors) == 1
      end)

    assert log =~ "Failed to get info of node #{node()}"
  end

  defp assert_node_info(info, node, health) do
    assert Enum.sort(Map.keys(info)) == [:health, :host, :node, :uptime_ms, :version]
    assert info.node == node
    assert [_name, host] = node |> to_string() |> String.split("@")
    assert info.host == host
    assert is_integer(info.uptime_ms) and info.uptime_ms >= 0
    assert info.version == to_string(Application.spec(:supavisor, :vsn))
    assert info.health == health
  end
end
