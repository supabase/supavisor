defmodule Supavisor.SynHandlerTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  require Logger
  alias Ecto.Adapters.SQL.Sandbox

  @tenant "syn_tenant"

  test "resolving conflict" do
    node2 = :"secondary@127.0.0.1"

    {:ok, pid2} = :erpc.call(node2, Supavisor, :start, [@tenant])
    Process.sleep(500)
    assert pid2 == Supavisor.get_global_sup(@tenant)
    assert node(pid2) == node2
    true = Node.disconnect(node2)
    Process.sleep(500)

    assert nil == Supavisor.get_global_sup(@tenant)
    {:ok, pid1} = Supavisor.start(@tenant)
    assert pid1 == Supavisor.get_global_sup(@tenant)
    assert node(pid1) == node()

    :pong = Node.ping(node2)
    Process.sleep(500)

    msg = "Resolving syn_tenant conflict, stop local pid"

    assert capture_log(fn -> Logger.warn(msg) end) =~
             msg

    assert pid2 == Supavisor.get_global_sup(@tenant)
    assert node(pid2) == node2
  end

  setup tags do
    pid = Sandbox.start_owner!(Supavisor.Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end
end
