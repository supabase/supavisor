defmodule Supavisor.Integration.WsProxyTest do
  use ExUnit.Case, async: false

  alias SupavisorWeb.WsProxy

  @moduletag integration: true

  @tenant "proxy_tenant_ps_enabled"

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    {:ok, user: db_conf[:username], database: db_conf[:database]}
  end

  defp start(params, client_ip \\ {127, 0, 0, 1}) do
    startup = params |> :pgo_protocol.encode_startup_message() |> IO.iodata_to_binary()
    state = %{WsProxy.init([]) | client_ip: client_ip}
    WsProxy.websocket_handle({:binary, startup}, state)
  end

  test "starts authentication", %{user: user, database: database} do
    assert {:ok, _state} = start([{"user", "#{user}.#{@tenant}"}, {"database", database}])
    assert_receive {:tcp, _, <<?R, _::binary>>}
  end

  test "passes the client's IP to Supavisor", %{user: user, database: database} do
    key = {@tenant, "10.0.0.1"}
    Supavisor.CircuitBreaker.open_local(key, :auth_error, System.system_time(:second) + 60)
    on_exit(fn -> Supavisor.CircuitBreaker.clear(key, :auth_error) end)

    # Logins from that IP are blocked, so the connection is turned away.
    start([{"user", "#{user}.#{@tenant}"}, {"database", database}], {10, 0, 0, 1})
    assert_receive {:tcp, _, <<?E, _::binary>> = error}
    assert error =~ "ECIRCUITBREAKER"
  end

  test "checks the tenant's allow list", %{user: user, database: database} do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "ws_allow_list_#{System.unique_integer([:positive])}"

    {:ok, _tenant} =
      Supavisor.Tenants.create_tenant(%{
        external_id: tenant,
        db_host: db_conf[:hostname],
        db_port: db_conf[:port],
        db_database: database,
        require_user: true,
        allow_list: ["10.0.0.0/8"],
        default_parameter_status: %{"server_version" => "15.0"},
        users: [
          %{
            "db_user" => user,
            "db_password" => db_conf[:password],
            "pool_size" => 1,
            "mode_type" => "transaction"
          }
        ]
      })

    on_exit(fn -> Supavisor.Tenants.delete_tenant_by_external_id(tenant) end)

    params = [{"user", "#{user}.#{tenant}"}, {"database", database}]
    assert {[{:binary, error}, :close], _state} = start(params, {192, 168, 0, 1})
    assert IO.iodata_to_binary(error) =~ "EADDRNOTALLOWED"
    assert {:ok, _state} = start(params, {10, 0, 0, 1})
  end
end
