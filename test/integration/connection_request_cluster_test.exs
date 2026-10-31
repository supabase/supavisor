defmodule Supavisor.Integration.ConnectionRequestClusterTest do
  use Supavisor.DataCase, async: false

  alias Postgrex, as: P
  alias Supavisor.Support.Cluster
  alias Supavisor.Support.Cluster.PortConfig

  @tenant_prefix "cluster_pool_tenant_"

  defp start_nodes do
    {:ok, peer1, node1} =
      Cluster.start_node_unclustered(
        :test_node_1,
        %PortConfig{
          proxy_port_transaction: 7678,
          proxy_port_session: 7679,
          session_proxy_ports: [17_100, 17_101, 17_102, 17_103],
          transaction_proxy_ports: [17_104, 17_105, 17_106, 17_107]
        }
      )

    {:ok, peer2, node2} =
      Cluster.start_node_unclustered(
        :test_node_2,
        %PortConfig{
          proxy_port_transaction: 7681,
          proxy_port_session: 7682,
          session_proxy_ports: [18_100, 18_101, 18_102, 18_103],
          transaction_proxy_ports: [18_104, 18_105, 18_106, 18_107]
        }
      )

    Node.connect(node1)
    Node.connect(node2)

    nodes = [node(), node1, node2]

    assert :ok = wait_until(fn -> peers_clustered?([node1, node2]) end, 5_000)

    ports = [
      Application.get_env(:supavisor, :proxy_port_transaction),
      :peer.call(peer1, Application, :get_env, [:supavisor, :proxy_port_transaction]),
      :peer.call(peer2, Application, :get_env, [:supavisor, :proxy_port_transaction])
    ]

    {nodes, ports}
  end

  # A peer that doesn't know the other one yet places every pool on itself, and the resulting :syn
  # conflict stops one of the pools and its clients. This node joined :accepting_pools before it was
  # named, so :syn doesn't sync its membership and peers never list it there.
  defp peers_clustered?(peers) do
    Enum.all?(peers, fn peer ->
      Enum.sort(:erpc.call(peer, Supavisor, :accepting_nodes, [])) == Enum.sort(peers)
    end)
  end

  # Forwards connection request events for this test's tenants from every node. Telemetry handlers run
  # in the emitting ClientHandler, so its logger metadata says whose request it is, which keeps other
  # tests' leftover connections out of the count. Evaluated as a string because the test module is not
  # loaded on the peer nodes.
  defp forward_events(nodes, ref) do
    code = """
    :telemetry.attach(
      {:connection_request_cluster_test, ref},
      [:supavisor, :client, :connection_request, :stop],
      fn _event, _measurements, metadata, _config ->
        project = Logger.metadata()[:project]

        if is_binary(project) and String.starts_with?(project, prefix),
          do: send(pid, {ref, node(), metadata})
      end,
      nil
    )
    """

    for node <- nodes do
      :erpc.call(node, Code, :eval_string, [
        code,
        [pid: self(), ref: ref, prefix: @tenant_prefix]
      ])
    end
  end

  defp collect(ref, acc \\ []) do
    receive do
      {^ref, node, metadata} -> collect(ref, [{node, metadata} | acc])
    after
      500 -> acc
    end
  end

  @tag cluster: true
  test "a request that is proxied to the pool's node is recorded once" do
    {nodes, ports} = start_nodes()
    db_conf = Application.get_env(:supavisor, Repo)
    ref = make_ref()

    clients_before = Registry.count(Supavisor.Registry.TenantClients)
    forward_events(nodes, ref)
    on_exit(fn -> :telemetry.detach({:connection_request_cluster_test, ref}) end)

    tasks =
      for i <- 1..10, port <- ports do
        Task.async(fn ->
          pid = self()

          {:ok, proxy} =
            P.start_link(
              hostname: db_conf[:hostname],
              port: port,
              database: db_conf[:database],
              password: db_conf[:password],
              username: db_conf[:username] <> "." <> "#{@tenant_prefix}#{i}",
              pool_size: 1,
              after_connect: fn _ -> send(pid, :connected) end
            )

          receive do
            :connected -> :ok
          end

          proxy
        end)
      end

    conns = Task.await_many(tasks, 15_000)

    try do
      assert length(conns) == 30

      # Guards against a vacuous pass: some requests must have been proxied to another node
      proxied =
        for node <- nodes, reduce: 0 do
          acc -> acc + :erpc.call(node, Registry, :count, [Supavisor.Registry.TenantProxyClients])
        end

      assert proxied > 0

      events = collect(ref)

      assert events |> Enum.filter(fn {_, meta} -> meta.outcome == :ok end) |> length() == 30
      assert Enum.filter(events, fn {_, meta} -> meta.outcome == :error end) == []
      assert Enum.filter(events, fn {_, meta} -> meta.mode == :proxy end) == []
    after
      # Leave no client registered on this node for the tests that run after, even on failure
      Enum.each(conns, &GenServer.stop/1)

      wait_until(
        fn -> Registry.count(Supavisor.Registry.TenantClients) <= clients_before end,
        5_000
      )
    end
  end
end
