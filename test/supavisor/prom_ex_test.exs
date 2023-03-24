defmodule Supavisor.PromExTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  require Logger
  alias Ecto.Adapters.SQL.Sandbox
  alias Supavisor.Monitoring.PromEx
  use Supavisor.DataCase
  alias Postgrex, as: P

  @tenant "prom_tenant"

  setup_all do
    db_conf = Application.get_env(:supavisor, Repo)

    {:ok, proxy} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: Application.get_env(:supavisor, :proxy_port),
        database: db_conf[:database],
        password: db_conf[:password],
        username: db_conf[:username] <> "." <> @tenant
      )

    %{proxy: proxy}
  end

  test "remove tenant tag upon termination", %{proxy: proxy} do
    P.query!(proxy, "select 1;", [])
    Process.sleep(500)
    metrics = PromEx.get_metrics()
    assert metrics =~ "tenant=\"#{@tenant}\""
    DynamicSupervisor.stop(proxy)
    Process.sleep(500)
    Supavisor.stop(@tenant)
    Process.sleep(500)
    refute PromEx.get_metrics() =~ "tenant=\"#{@tenant}\""
  end
end
