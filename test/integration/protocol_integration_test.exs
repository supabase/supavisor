defmodule Supavisor.Integration.ProtocolIntegrationTest do
  use Supavisor.DataCase, async: false

  alias Supavisor.Protocol.Server
  alias Supavisor.Support.ProtocolClient
  require Server

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
      password = db_conf[:password]

      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

      # authenticate/3 sends a user-only startup without database parameter
      ProtocolClient.authenticate(sock, "#{user}.#{tenant}", password)

      # Verify the connection defaults to the correct database
      :ok = :gen_tcp.send(sock, :pgo_protocol.encode_query_message("SELECT current_database()"))
      {:ok, query_result} = :gen_tcp.recv(sock, 0, 5000)
      {pkts, ""} = Supavisor.Protocol.split_pkts(query_result)
      assert [_, <<?D, _::32, 1::16, len::32, db_name::binary-size(len)>>, _, _] = pkts
      assert db_name == to_string(db_conf[:database])
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

  describe "authentication method selection" do
    setup do
      Supavisor.Support.SSLHelper.setup_downstream_certs()
      %{port: Application.get_env(:supavisor, :proxy_port_transaction)}
    end

    test "requests SCRAM-SHA-256 when client connects without SSL", %{port: port} do
      tenant = List.first(@tenants)
      db_conf = Application.get_env(:supavisor, Supavisor.Repo)
      user = db_conf[:username]

      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

      startup =
        :pgo_protocol.encode_startup_message([
          {"user", "#{user}.#{tenant}"},
          {"database", to_string(db_conf[:database])}
        ])

      :ok = :gen_tcp.send(sock, startup)

      {:ok, <<?R, _::32, auth_type::32, _::binary>>} = :gen_tcp.recv(sock, 0, 5000)
      # 10 = AuthenticationSASL
      assert auth_type == 10
    end

    # Temporarily reverted: password-auth-over-TLS optimization for non-JIT
    # tenants was disabled, so these expectations no longer hold.
    # test "requests cleartext password when client connects with SSL", %{port: port} do
    #   tenant = List.first(@tenants)
    #   db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    #   user = db_conf[:username]
    #
    #   {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    #   :ok = :gen_tcp.send(tcp, Server.ssl_request_message())
    #   {:ok, "S"} = :gen_tcp.recv(tcp, 1, 5000)
    #   {:ok, ssl} = :ssl.connect(tcp, [verify: :verify_none, active: false], 5000)
    #
    #   startup =
    #     :pgo_protocol.encode_startup_message([
    #       {"user", "#{user}.#{tenant}"},
    #       {"database", to_string(db_conf[:database])}
    #     ])
    #
    #   :ok = :ssl.send(ssl, startup)
    #
    #   {:ok, <<?R, _::32, auth_type::32, _::binary>>} = :ssl.recv(ssl, 0, 5000)
    #   # 3 = AuthenticationCleartextPassword
    #   assert auth_type == 3
    # end

    test "proxied connection requests SCRAM-SHA-256 without client_tls option" do
      tenant = List.first(@tenants)
      db_conf = Application.get_env(:supavisor, Supavisor.Repo)
      user = db_conf[:username]

      [local_port | _] = Application.get_env(:supavisor, :transaction_proxy_ports)
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", local_port, [:binary, active: false])

      startup =
        :pgo_protocol.encode_startup_message([
          {"user", "#{user}.#{tenant}"},
          {"database", to_string(db_conf[:database])}
        ])

      :ok = :gen_tcp.send(sock, startup)

      {:ok, <<?R, _::32, auth_type::32, _::binary>>} = :gen_tcp.recv(sock, 0, 5000)
      # 10 = AuthenticationSASL
      assert auth_type == 10
    end

    # Temporarily reverted: password-auth-over-TLS optimization for non-JIT
    # tenants was disabled, so these expectations no longer hold.
    # test "proxied connection requests cleartext password with client_tls option" do
    #   tenant = List.first(@tenants)
    #   db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    #   user = db_conf[:username]
    #
    #   [local_port | _] = Application.get_env(:supavisor, :transaction_proxy_ports)
    #   {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", local_port, [:binary, active: false])
    #
    #   startup =
    #     :pgo_protocol.encode_startup_message([
    #       {"user", "#{user}.#{tenant}"},
    #       {"database", to_string(db_conf[:database])},
    #       {"options", "--client_tls=true"}
    #     ])
    #
    #   :ok = :gen_tcp.send(sock, startup)
    #
    #   {:ok, <<?R, _::32, auth_type::32, _::binary>>} = :gen_tcp.recv(sock, 0, 5000)
    #   # 3 = AuthenticationCleartextPassword
    #   assert auth_type == 3
    # end
  end
end
