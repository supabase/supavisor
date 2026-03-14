defmodule Supavisor.Integration.ProtocolIntegrationTest do
  use Supavisor.DataCase, async: false

  alias Supavisor.Protocol.Server

  @tenants ["proxy_tenant_ps_enabled", "proxy_tenant_ps_disabled"]

  describe "startup packet edge cases" do
    setup do
      %{port: Application.get_env(:supavisor, :proxy_port_transaction)}
    end

    test "closes connection when startup packet is too large", %{port: port} do
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

      padding = :binary.copy(<<0>>, 1100)
      bin = <<1108::32, 3::16, 0::16, padding::binary>>

      :ok = :gen_tcp.send(sock, bin)
      assert {:ok, data} = :gen_tcp.recv(sock, 0, 5000)

      assert {:ok, %Server.Pkt{tag: :error_response, payload: payload}, ""} =
               Server.decode_pkt(data)

      assert %{
               "C" => "08P01",
               "M" =>
                 "(ESTARTUPPACKETTOOLARGE) Startup packet too large: 1108 bytes (max 1024 bytes)"
             } = payload

      assert {:error, :closed} = :gen_tcp.recv(sock, 0, 5000)
    end

    test "closes connection when startup packet is malformed", %{port: port} do
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

      bin = <<13::32, 3::16, 0::16, "nope", 0>>

      :ok = :gen_tcp.send(sock, bin)
      assert {:ok, data} = :gen_tcp.recv(sock, 0, 5000)

      assert {:ok, %Server.Pkt{tag: :error_response, payload: payload}, ""} =
               Server.decode_pkt(data)

      assert %{
               "C" => "08P01",
               "M" => "(ESTARTUPMESSAGE) Invalid startup message: :bad_startup_payload"
             } = payload

      assert {:error, :closed} = :gen_tcp.recv(sock, 0, 5000)
    end

    test "handles startup packet with no database parameter", %{port: port} do
      db_conf = Application.get_env(:supavisor, Supavisor.Repo)
      tenant = List.first(@tenants)
      user = db_conf[:username]
      username = user <> "." <> tenant
      password = db_conf[:password]

      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

      # Send startup message with only user, no database (uses pgo encoding)
      startup = :pgo_protocol.encode_startup_message([{"user", username}])
      :ok = :gen_tcp.send(sock, startup)

      # Receive SASL auth request (type 10)
      {:ok, <<?R, _::32, 10::32, methods_bin::binary>>} = :gen_tcp.recv(sock, 0, 5000)
      methods = :pgo_protocol.decode_strings(methods_bin)
      assert "SCRAM-SHA-256" in methods

      # SCRAM client-first
      nonce = :pgo_scram.get_nonce(16)
      client_first = :pgo_scram.get_client_first(user, nonce)
      client_first_size = :erlang.iolist_size(client_first)

      sasl_initial = ["SCRAM-SHA-256", 0, <<client_first_size::32>>, client_first]
      :ok = :gen_tcp.send(sock, :pgo_protocol.encode_scram_response_message(sasl_initial))

      # Receive server-first message (type 11)
      {:ok, <<?R, _::32, 11::32, server_first::binary>>} = :gen_tcp.recv(sock, 0, 5000)

      # SCRAM client-final
      server_first_parts = :pgo_scram.parse_server_first(server_first, nonce)

      {client_final, server_proof} =
        :pgo_scram.get_client_final(server_first_parts, nonce, user, password)

      :ok = :gen_tcp.send(sock, :pgo_protocol.encode_scram_response_message(client_final))

      # Receive server-final (type 12) + auth ok + params + ReadyForQuery
      {:ok, auth_data} = :gen_tcp.recv(sock, 0, 5000)

      {auth_pkts, ""} = Supavisor.Protocol.split_pkts(auth_data)

      <<?R, _::32, 12::32, server_final::binary>> = hd(auth_pkts)
      {:ok, ^server_proof} = :pgo_scram.parse_server_final(server_final)

      recv_until_ready_for_query(sock, auth_data)

      # Send simple query to verify database defaults correctly
      :ok = :gen_tcp.send(sock, :pgo_protocol.encode_query_message("SELECT current_database()"))

      {:ok, query_result} = :gen_tcp.recv(sock, 0, 5000)
      expected_db = to_string(db_conf[:database])
      db_len = byte_size(expected_db)

      # RowDescription + DataRow(1 col with db name) + CommandComplete + ReadyForQuery
      {[_, <<?D, _d_len::32, 1::16, ^db_len::32, ^expected_db::binary-size(db_len)>>, _, _], ""} =
        Supavisor.Protocol.split_pkts(query_result)
    end

    # Regression: issue #854
    test "handles startup packet where options has an empty value", %{port: port} do
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

      bin =
        <<91::32, 3::16, 0::16, "user", 0, "postgres.proxy_tenant_ps_enabled", 0, "database", 0,
          "postgres", 0, "options", 0, 0, "client_encoding", 0, "UTF8", 0, 0>>

      :ok = :gen_tcp.send(sock, bin)
      {:ok, response} = :gen_tcp.recv(sock, 0, 5000)

      # Authentication response
      assert <<?R, _::binary>> = response

      :gen_tcp.close(sock)
    end
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
