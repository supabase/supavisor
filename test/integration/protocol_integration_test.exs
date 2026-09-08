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

    test "closes connection when no startup packet is sent", %{port: port} do
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

      assert {:error, :closed} = :gen_tcp.recv(sock, 0, 6_000)
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

  describe "client_ip forwarded on proxied JIT connections" do
    # Stands in for the tenant's JIT API. Records the request body (which carries
    # `rhost`, the IP Supavisor attributes the connection to) and rejects the token
    # so the connection is terminated cleanly without reaching the database.
    defmodule JitApiStub do
      @behaviour Plug
      import Plug.Conn

      def init(test_pid), do: test_pid

      def call(conn, test_pid) do
        {:ok, body, conn} = read_body(conn)
        send(test_pid, {:jit_request, Jason.decode!(body)})

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(403, Jason.encode!(%{"message" => "forbidden"}))
      end
    end

    @forwarded_ip "203.0.113.9"
    @token "sbp_0000000000000000000000000000000000000000"

    setup do
      Supavisor.Support.SSLHelper.setup_downstream_certs()

      ref = :"jit_api_stub_#{System.unique_integer([:positive])}"

      start_supervised!(
        {Plug.Cowboy, scheme: :http, plug: {JitApiStub, self()}, options: [port: 0, ref: ref]}
      )

      jit_port = :ranch.get_port(ref)

      db_conf = Application.get_env(:supavisor, Supavisor.Repo)
      tenant_id = "jit_client_ip_tenant_#{System.unique_integer([:positive])}"

      {:ok, _tenant} =
        Supavisor.Tenants.create_tenant(%{
          db_database: db_conf[:database],
          db_host: to_string(db_conf[:hostname]),
          db_port: db_conf[:port],
          external_id: tenant_id,
          require_user: true,
          default_parameter_status: %{"server_version" => "15.0"},
          use_jit: true,
          jit_api_url: "http://127.0.0.1:#{jit_port}/jit",
          users: [
            %{
              "db_user" => to_string(db_conf[:username]),
              "db_password" => to_string(db_conf[:password]),
              "pool_size" => 3,
              "mode_type" => "transaction"
            }
          ]
        })

      on_exit(fn -> Supavisor.Tenants.delete_tenant_by_external_id(tenant_id) end)

      %{
        user: "#{db_conf[:username]}.#{tenant_id}",
        database: to_string(db_conf[:database]),
        local_port: hd(Application.get_env(:supavisor, :transaction_proxy_ports)),
        public_port: Application.get_env(:supavisor, :proxy_port_transaction)
      }
    end

    test "local listener attributes the connection to the forwarded client_ip", ctx do
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", ctx.local_port, [:binary, active: false])

      # This is what a peer node's proxy DbHandler sends when forwarding a client
      # that authenticated with JIT over TLS (see DbHandler.send_startup/4).
      jit_handshake(
        {:gen_tcp, sock},
        ctx,
        "--jit=true --client_tls=true --client_ip=#{@forwarded_ip}"
      )

      assert_receive {:jit_request, %{"rhost" => @forwarded_ip, "role" => "postgres"}}, 5_000
    end

    test "local listener falls back to the socket peer without client_ip", ctx do
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", ctx.local_port, [:binary, active: false])

      jit_handshake({:gen_tcp, sock}, ctx, "--jit=true --client_tls=true")

      assert_receive {:jit_request, %{"rhost" => "127.0.0.1", "role" => "postgres"}}, 5_000
    end

    test "public listener ignores client_ip supplied by the client", ctx do
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.public_port, [:binary, active: false])
      :ok = :gen_tcp.send(tcp, Server.ssl_request_message())
      {:ok, "S"} = :gen_tcp.recv(tcp, 1, 5_000)
      {:ok, ssl} = :ssl.connect(tcp, [verify: :verify_none, active: false], 5_000)

      # An external client must not be able to pick the IP the JIT API sees.
      jit_handshake({:ssl, ssl}, ctx, "--jit=true --client_ip=#{@forwarded_ip}")

      assert_receive {:jit_request, %{"rhost" => "127.0.0.1", "role" => "postgres"}}, 5_000
    end

    # Sends the startup message, answers the cleartext password request with a JIT
    # token and reads the server's (error) reply.
    defp jit_handshake({mod, sock}, ctx, options) do
      startup =
        :pgo_protocol.encode_startup_message([
          {"user", ctx.user},
          {"database", ctx.database},
          {"options", options}
        ])

      :ok = mod.send(sock, startup)

      # 3 = AuthenticationCleartextPassword
      {:ok, <<?R, 8::32, 3::32>>} = mod.recv(sock, 0, 5_000)

      password_message = <<?p, byte_size(@token) + 5::32, @token::binary, 0>>
      :ok = mod.send(sock, password_message)

      assert {:ok, <<?E, _::binary>>} = mod.recv(sock, 0, 5_000)
    end
  end
end
