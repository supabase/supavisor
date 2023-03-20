defmodule Supavisor.SynHandlerTest do
  use ExUnit.Case, async: false
  alias Ecto.Adapters.SQL.Sandbox

  @tenant "proxy_tenant"

  test "resolving conflict" do
    node2 = :"secondary@127.0.0.1"
    {:ok, pid2} = :erpc.call(node2, Supavisor, :start, [@tenant])
    true = Node.disconnect(node2)
    {:ok, pid1} = Supavisor.start(@tenant)
    :pong = Node.ping(node2)
    :timer.sleep(250)
    refute Process.alive?(pid1)
    assert pid2 == Supavisor.get_global_sup(@tenant)
  end

  setup tags do
    pid = Sandbox.start_owner!(Supavisor.Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end
end
