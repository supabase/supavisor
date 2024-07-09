defmodule Supavisor.Integration.SingleConnectionTest do
  require Logger
  use Supavisor.DataCase, async: true
  alias Postgrex, as: P

  @tenant "proxy_tenant1"

  test "connects to database and executes a simple query" do
    db_conf = Application.get_env(:supavisor, Repo)

    args = [
      hostname: db_conf[:hostname],
      port: Application.get_env(:supavisor, :proxy_port_transaction),
      database: "postgres",
      password: db_conf[:password],
      username: "transaction.#{@tenant}"
    ]

    spawn(fn ->
      {:ok, pid} =
        args
        |> Keyword.put_new(:caller, self())
        |> Supavisor.SimpleConnection.connect()

      assert %Postgrex.Result{rows: [["1"]]} =
               Postgrex.SimpleConnection.call(pid, {:query, "SELECT 1"})
    end)

    :timer.sleep(250)

    # check that the connection dies after the caller dies
    assert Enum.filter(Process.list(), fn pid ->
             Process.info(pid)[:dictionary][:auth_host] == db_conf[:hostname]
           end) == []
  end
end
