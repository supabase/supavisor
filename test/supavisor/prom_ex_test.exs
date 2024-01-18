defmodule Supavisor.PromExTest do
  use ExUnit.Case, async: true
  require Logger
  alias Supavisor.Monitoring.PromEx
  use Supavisor.DataCase
  alias Postgrex, as: P

  @tenant "prom_tenant"

  setup_all do
    db_conf = Application.get_env(:supavisor, Repo)

    {:ok, proxy} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: Application.get_env(:supavisor, :proxy_port_transaction),
        database: db_conf[:database],
        password: db_conf[:password],
        username: db_conf[:username] <> "." <> @tenant,
        socket_dir: nil
      )

    %{proxy: proxy, user: db_conf[:username], db_name: db_conf[:database]}
  end

  test "remove tenant tag upon termination", %{proxy: proxy, user: user, db_name: db_name} do
    P.query!(proxy, "select 1;", [])
    Process.sleep(500)
    metrics = PromEx.get_metrics()
    assert metrics =~ "tenant=\"#{@tenant}\""
    GenServer.stop(proxy)
    Process.sleep(500)
    Supavisor.stop({{:single, @tenant}, user, :transaction, db_name})
    Process.sleep(500)
    refute PromEx.get_metrics() =~ "tenant=\"#{@tenant}\""
  end
end
