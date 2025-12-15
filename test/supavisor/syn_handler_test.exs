defmodule Supavisor.SynHandlerTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  require Logger
  alias Ecto.Adapters.SQL.Sandbox
  alias Supavisor.Support.Cluster

  @id {{:single, "syn_tenant"}, "postgres", :session, "postgres", nil}

  @tag cluster: true
  test "resolving conflict" do
    {:ok, peer, node2} = Cluster.start_node_unclustered(:peer.random_name())

    secret = %Supavisor.ClientHandler.Auth.PasswordSecrets{
      user: "postgres",
      password: "postgres"
    }

    auth_secret = {:password, fn -> secret end}
    {:ok, pid2} = :peer.call(peer, Supavisor.FixturesHelpers, :start_pool, [@id, secret])
    assert :peer.call(peer, Supavisor, :get_global_sup, [@id]) == pid2
    assert node(pid2) == node2

    assert nil == Supavisor.get_global_sup(@id)
    {:ok, pid1} = Supavisor.start(@id, auth_secret)
    assert pid1 == Supavisor.get_global_sup(@id)
    assert node(pid1) == node()

    true = Node.connect(node2)
    Process.sleep(500)

    msg = "Resolving syn_tenant conflict, stop local pid"

    assert capture_log(fn -> Logger.warning(msg) end) =~ msg

    assert pid2 == Supavisor.get_global_sup(@id)
    assert node(pid2) == node2
  end

  setup tags do
    pid = Sandbox.start_owner!(Supavisor.Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end
end
