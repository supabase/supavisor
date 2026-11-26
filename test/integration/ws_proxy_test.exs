defmodule Supavisor.Integration.WsProxyTest do
  use ExUnit.Case, async: false

  alias SupavisorWeb.WsProxy

  @moduletag integration: true

  @tenant "proxy_tenant_ps_enabled"

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    {:ok, user: db_conf[:username], database: db_conf[:database]}
  end

  defp start(params, client_ip \\ "127.0.0.1") do
    startup = params |> :pgo_protocol.encode_startup_message() |> IO.iodata_to_binary()
    state = %{WsProxy.init([]) | client_ip: client_ip}
    {:ok, _state} = WsProxy.websocket_handle({:binary, startup}, state)
  end

  test "starts authentication", %{user: user, database: database} do
    start([{"user", "#{user}.#{@tenant}"}, {"database", database}])
    assert_receive {:tcp, _, <<?R, _::binary>>}
  end

  test "passes the client's IP to Supavisor", %{user: user, database: database} do
    key = {@tenant, "10.0.0.1"}
    Supavisor.CircuitBreaker.open_local(key, :auth_error, System.system_time(:second) + 60)
    on_exit(fn -> Supavisor.CircuitBreaker.clear(key, :auth_error) end)

    # Logins from that IP are blocked, so the connection is turned away.
    start([{"user", "#{user}.#{@tenant}"}, {"database", database}], "10.0.0.1")
    assert_receive {:tcp, _, <<?E, _::binary>> = error}
    assert error =~ "ECIRCUITBREAKER"
  end
end
