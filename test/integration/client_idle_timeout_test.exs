defmodule Supavisor.Integration.ClientIdleTimeoutTest do
  use Supavisor.DataCase, async: false

  @moduletag :integration

  @idle_timeout_ms 1000

  setup do
    %{db_conf: Application.get_env(:supavisor, Supavisor.Repo)}
  end

  test "server disconnects a client that sits idle past client_idle_timeout", %{db_conf: db_conf} do
    {:gen_tcp, sock} = db_conf |> idle_tenant() |> scram_connect()

    assert {:error, :closed} = :gen_tcp.recv(sock, 0, @idle_timeout_ms * 5)
  end

  # Creates a require_user tenant with client_idle_timeout set.
  defp idle_tenant(db_conf) do
    suffix = :crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower)
    tenant_id = "idle_timeout_#{System.unique_integer([:positive])}_#{suffix}"

    {:ok, _} =
      Supavisor.Tenants.create_tenant(%{
        db_host: db_conf[:hostname],
        db_port: db_conf[:port],
        db_database: db_conf[:database],
        external_id: tenant_id,
        require_user: true,
        default_parameter_status: %{"server_version" => "15.0"},
        client_idle_timeout: @idle_timeout_ms,
        client_heartbeat_interval: 0,
        users: [
          %{
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 2,
            "max_clients" => 10,
            "mode_type" => "transaction",
            "is_manager" => true
          }
        ]
      })

    on_exit(fn -> Supavisor.Tenants.delete_tenant_by_external_id(tenant_id) end)

    %{
      tenant: tenant_id,
      port: Application.get_env(:supavisor, :proxy_port_transaction),
      user: db_conf[:username],
      password: db_conf[:password],
      database: to_string(db_conf[:database])
    }
  end

  defp scram_connect(%{tenant: tenant, port: port, user: user, password: password, database: db}) do
    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

    startup =
      :pgo_protocol.encode_startup_message([{"user", "#{user}.#{tenant}"}, {"database", db}])

    :ok = :gen_tcp.send(sock, startup)

    # SASL auth request
    {:ok, <<?R, _::32, 10::32, _methods::binary>>} = :gen_tcp.recv(sock, 0, 5000)

    # SCRAM client-first
    nonce = :pgo_scram.get_nonce(16)
    client_first = :pgo_scram.get_client_first(user, nonce)
    client_first_size = :erlang.iolist_size(client_first)
    sasl_initial = ["SCRAM-SHA-256", 0, <<client_first_size::32>>, client_first]
    :ok = :gen_tcp.send(sock, :pgo_protocol.encode_scram_response_message(sasl_initial))

    # SCRAM server-first
    {:ok, <<?R, _::32, 11::32, server_first::binary>>} = :gen_tcp.recv(sock, 0, 5000)
    server_first_parts = :pgo_scram.parse_server_first(server_first, nonce)

    # SCRAM client-final
    {client_final, server_proof} =
      :pgo_scram.get_client_final(server_first_parts, nonce, user, password)

    :ok = :gen_tcp.send(sock, :pgo_protocol.encode_scram_response_message(client_final))

    # SCRAM server-final + auth ok + params + ReadyForQuery
    {:ok, auth_data} = :gen_tcp.recv(sock, 0, 5000)

    {[<<?R, _::32, 12::32, server_final::binary>> | _], ""} =
      Supavisor.Protocol.split_pkts(auth_data)

    {:ok, ^server_proof} = :pgo_scram.parse_server_final(server_final)
    recv_until_ready_for_query(sock, auth_data)

    {:gen_tcp, sock}
  end

  defp recv_until_ready_for_query(sock, buf) do
    {pkts, ""} = Supavisor.Protocol.split_pkts(buf)

    if Enum.any?(pkts, &match?(<<?Z, _::binary>>, &1)) do
      :ok
    else
      {:ok, more} = :gen_tcp.recv(sock, 0, 5000)
      recv_until_ready_for_query(sock, more)
    end
  end
end
