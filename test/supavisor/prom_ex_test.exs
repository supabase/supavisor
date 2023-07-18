defmodule Supavisor.PromExTest do
  use ExUnit.Case, async: false
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
        username: db_conf[:username] <> "." <> @tenant
      )

    %{proxy: proxy, user: db_conf[:username]}
  end

  test "remove tenant tag upon termination", %{proxy: proxy, user: user} do
    P.query!(proxy, "select 1;", [])
    Process.sleep(500)
    metrics = PromEx.get_metrics()
    assert metrics =~ "tenant=\"#{@tenant}\""
    DynamicSupervisor.stop(proxy, user)
    Process.sleep(500)
    Supavisor.stop(@tenant, user)
    Process.sleep(500)
    refute PromEx.get_metrics() =~ "tenant=\"#{@tenant}\""
  end
end
