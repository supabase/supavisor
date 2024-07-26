defmodule Supavisor.SynHandlerTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  require Logger
  alias Ecto.Adapters.SQL.Sandbox
  alias Supavisor.Support.Cluster

  @id {{:single, "syn_tenant"}, "postgres", :session, "postgres"}

  test "resolving conflict" do
    {:ok, _pid, node2} = Cluster.start_node()

    secret = %{alias: "postgres"}
    auth_secret = {:password, fn -> secret end}
    {:ok, pid2} = :erpc.call(node2, Supavisor.FixturesHelpers, :start_pool, [@id, secret])
    Process.sleep(500)
    assert pid2 == Supavisor.get_global_sup(@id)
    assert node(pid2) == node2
    true = Node.disconnect(node2)
    Process.sleep(1000)

    assert nil == Supavisor.get_global_sup(@id)
    {:ok, pid1} = Supavisor.start(@id, auth_secret)
    assert pid1 == Supavisor.get_global_sup(@id)
    assert node(pid1) == node()

    :pong = Node.ping(node2)
    Process.sleep(500)

    msg = "Resolving syn_tenant conflict, stop local pid"

    assert capture_log(fn -> Logger.warning(msg) end) =~
             msg

    assert pid2 == Supavisor.get_global_sup(@id)
    assert node(pid2) == node2
  end

  setup tags do
    pid = Sandbox.start_owner!(Supavisor.Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end
end
