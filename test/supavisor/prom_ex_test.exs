defmodule Supavisor.PromExTest do
  use ExUnit.Case, async: true
  use Supavisor.DataCase

  alias Supavisor.Monitoring.PromEx

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
        socket_dir: nil,
        show_sensitive_data_on_connection_error: true
      )

    assert :idle == DBConnection.status(proxy)

    %{proxy: proxy, user: db_conf[:username], db_name: db_conf[:database]}
  end

  test "remove tenant tag upon termination", %{proxy: proxy, user: user, db_name: db_name} do
    assert PromEx.get_metrics() =~ "tenant=\"#{@tenant}\""

    GenServer.stop(proxy)
    Supavisor.stop({{:single, @tenant}, user, :transaction, db_name})

    Process.sleep(500)

    refute PromEx.get_metrics() =~ "tenant=\"#{@tenant}\""
  end

  test "clean_string/1 removes extra spaces from metric string" do
    input =
      "db_name=\"postgres \",mode=\" transaction\",tenant=\"dev_tenant \n\",type=\"\n  single\",user=\"\npostgres\n\""

    expected_output =
      "db_name=\"postgres\",mode=\"transaction\",tenant=\"dev_tenant\",type=\"single\",user=\"postgres\""

    assert expected_output == PromEx.clean_string(input)
  end
end
