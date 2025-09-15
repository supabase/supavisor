defmodule Supavisor.DbHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.DbHandler, as: Db

  # import Mock
  @id {{:single, "tenant"}, "user", :transaction, "postgres", nil}

  defp sockpair do
    {:ok, listen} = :gen_tcp.listen(0, mode: :binary, active: false)
    {:ok, {address, port}} = :inet.sockname(listen)
    this = self()
    ref = make_ref()

    spawn(fn ->
      {:ok, recv} = :gen_tcp.accept(listen)

      :gen_tcp.controlling_process(recv, this)

      send(this, {ref, recv})
    end)

    {:ok, send} = :gen_tcp.connect(address, port, mode: :binary, active: false)
    assert_receive {^ref, recv}

    {send, recv}
  end

  describe "init/1" do
    test "starts with correct state" do
      args = %{
        id: @id,
        auth: %{},
        tenant: {:single, "test_tenant"},
        user_alias: "test_user_alias",
        user: "user",
        mode: :transaction,
        replica_type: :single,
        log_level: nil,
        reconnect_retries: 5,
        tenant_feature_flags: %{}
      }

      {:ok, :connect, data, {_, next_event, _}} = Db.init(args)
      assert next_event == :internal
      assert data.sock == nil
      assert data.caller == nil
      assert data.sent == false
      assert data.auth == args.auth
      assert data.tenant == args.tenant
      assert data.db_state == nil
      assert data.parameter_status == %{}
      assert data.nonce == nil
      assert data.server_proof == nil
    end
  end

  describe "handle_event/4" do
    test "db is available" do
      {:ok, sock} = :gen_tcp.listen(0, mode: :binary, active: false)
      {:ok, {host, port}} = :inet.sockname(sock)

      secrets = fn -> %{user: "some user", db_user: "some user"} end

      auth = %{
        host: host,
        port: port,
        user: "some user",
        require_user: true,
        database: "some database",
        application_name: "some application name",
        ip_version: :inet,
        secrets: secrets
      }

      state =
        Db.handle_event(:internal, nil, :connect, %{
          auth: auth,
          sock: {:gen_tcp, nil},
          id: @id,
          proxy: false
        })

      assert {:next_state, :authentication,
              %{
                auth: %{
                  application_name: "some application name",
                  database: "some database",
                  host: ^host,
                  port: ^port,
                  user: "some user",
                  require_user: true,
                  ip_version: :inet,
                  secrets: ^secrets
                },
                sock: {:gen_tcp, _},
                id: @id,
                proxy: false
              }} = state
    end

    test "db is not available" do
      # We assume that there is nothing running on this port
      # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
      {host, port} = {{127, 0, 0, 1}, 12345}

      secrets = fn -> %{user: "some user", db_user: "some user"} end

      auth = %{
        id: @id,
        host: host,
        port: port,
        user: "some user",
        database: "some database",
        application_name: "some application name",
        require_user: true,
        ip_version: :inet,
        secrets: secrets
      }

      state =
        Db.handle_event(:internal, nil, :connect, %{
          auth: auth,
          sock: nil,
          id: @id,
          proxy: false,
          reconnect_retries: 5
        })

      assert state == {:keep_state_and_data, {:state_timeout, 2_500, :connect}}
    end

    test "rejects connection when DB responds with SSL negotiation 'N'" do
      {:ok, listen} = :gen_tcp.listen(0, mode: :binary, active: false)
      {:ok, {host, port}} = :inet.sockname(listen)

      this = self()

      spawn(fn ->
        {:ok, recv} = :gen_tcp.accept(listen)

        :gen_tcp.controlling_process(recv, this)

        {:ok, _message} = :gen_tcp.recv(recv, 0)

        :gen_tcp.send(recv, <<?N>>)
      end)

      secrets = fn -> %{user: "some user", db_user: "some user"} end

      auth = %{
        host: host,
        port: port,
        user: "some user",
        require_user: true,
        database: "some database",
        application_name: "some application name",
        ip_version: :inet,
        secrets: secrets,
        upstream_ssl: true
      }

      data = %{
        auth: auth,
        sock: {:gen_tcp, nil},
        id: @id,
        proxy: false,
        reconnect_retries: 6,
        client_sock: nil
      }

      assert {:keep_state_and_data, {:state_timeout, 2500, :connect}} ==
               Db.handle_event(:internal, nil, :connect, data)
    end
  end

  describe "handle_event/4 info tcp authentication authentication_cleartext_password payload events" do
    test "keeps state while sending the cleartext password" do
      # `82` is `?R`, which identifies the payload tag as `:authentication`
      # `0, 0, 0, 8` is the packet length
      # `0, 0, 0, 3` is the authentication type, identified as `:authentication_cleartext_password`
      bin = <<82, 0, 0, 0, 8, 0, 0, 0, 3>>

      {a, b} = sockpair()

      content = {:tcp, b, bin}

      data = %{
        auth: %{
          password: fn -> "some_password" end,
          user: "some_user",
          method: :password
        },
        sock: {:gen_tcp, a}
      }

      assert {:keep_state, ^data} = Db.handle_event(:info, content, :authentication, data)

      assert {:ok, message} = :gen_tcp.recv(b, 0)

      # client response
      # p, identifies the payload as password message
      # 0,0,0,9 is the payload length (length field + null terminated string)
      # 41, 41, 41, 41, 00 is the null terminated password string
      password = <<data.auth.password.()::binary, 0>>

      assert message ==
               <<?p, byte_size(password) + 4::32-big, password::binary>>
    end
  end

  describe "handle_event/4 info tcp authentication authentication_sasl_password payload events" do
    setup do
      {send, recv} = sockpair()

      data = %{
        auth: %{
          user: "user",
          require_user: false,
          secrets: fn -> %{user: "user", password: "pass"} end
        },
        sock: {:gen_tcp, send},
        nonce: "some nonce"
      }

      %{data: data, recv: recv}
    end

    test "handles SASL authentication and sets nonce", %{data: data, recv: recv} do
      # ``?R` identifies the payload tag as `:authentication`
      # `22::32` is the packet length
      # `10::32` is the authentication type, identified as `:authentication_sasl_password`
      # `"SCRAM-SHA-256", 0` is payload`
      bin = <<?R, 22::32, 10::32, "SCRAM-SHA-256", 0>>

      content = {:tcp, recv, bin}

      assert {:keep_state, %{nonce: nonce}} =
               Db.handle_event(:info, content, :authentication, data)

      assert nonce != data.nonce
    end

    test "does not set a nonce when SASL authentication fails", %{data: data, recv: recv} do
      bin = <<?R, 21::32, 10::32, "SCRAM-SHA-256">>

      content = {:tcp, recv, bin}

      assert {:keep_state, %{nonce: nil}} = Db.handle_event(:info, content, :authentication, data)
    end
  end

  describe "handle_event/4 info tcp authentication authentication_server_first_message payload events" do
    test "handles server first message" do
      server_first = "r=nonce12345nonce67890,s=c2FsdA==,i=4096"
      pkt_len = 8 + byte_size(server_first)
      bin = <<?R, pkt_len::32, 11::32, server_first::binary>>

      {a, b} = sockpair()
      content = {:tcp, b, bin}

      secrets = %{
        user: "user",
        password: "password",
        client_key: :binary.copy(<<1>>, 32),
        stored_key: :binary.copy(<<2>>, 32),
        server_key: :binary.copy(<<3>>, 32)
      }

      data = %{
        auth: %{
          user: "user",
          secrets: fn -> secrets end,
          require_user: false,
          nonce: "nonce12345"
        },
        sock: {:gen_tcp, a},
        nonce: "nonce12345",
        server_proof: nil
      }

      assert {:keep_state, %{server_proof: server_proof}} =
               Db.handle_event(:info, content, :authentication, data)

      assert server_proof != data.server_proof
    end
  end

  describe "handle_event/4 info tcp error_response" do
    test "handles server invalid password" do
      bin =
        <<?E, 51::32, "SFATAL", 0, "VFATAL", 0, "C28P01", 0, "wrong", 0, "something", 0, "auth",
          0, "error", 0>>

      {_a, b} = sockpair()
      content = {:tcp, b, bin}

      data = %{id: @id, proxy: false, user: "some user"}

      assert {:stop, :invalid_password, ^data} =
               Db.handle_event(:info, content, :authentication, data)
    end

    test "handles server encode and forward error" do
      bin = <<?E, 4::32>>

      {_a, b} = sockpair()
      content = {:tcp, b, bin}

      assert {:stop, {:encode_and_forward, []}} =
               Db.handle_event(:info, content, :authentication, %{})
    end
  end

  describe "handle_event/4 info tcp authentication authentication_md5_password payload events" do
    setup do
      # `82` is `?R`, which identifies the payload tag as `:authentication`
      # `0, 0, 0, 12` is the packet length
      # `0, 0, 0, 5` is the authentication type, identified as `:authentication_md5_password`
      # `100, 100, 100, 100` is the md5 salt from db, a random 4 bytes value
      bin = <<82, 0, 0, 0, 12, 0, 0, 0, 5, 100, 100, 100, 100>>

      {send, recv} = sockpair()

      data = %{sock: {:gen_tcp, send}}

      content = {:tcp, recv, bin}

      %{data: data, send: send, recv: recv, content: content}
    end

    test "keeps state while sending the digested md5 using the password method", %{
      data: data,
      recv: recv,
      content: content
    } do
      auth = %{
        password: fn -> "some_password" end,
        user: "some_user",
        method: :password
      }

      data = Map.put(data, :auth, auth)

      assert {:keep_state, ^data} = Db.handle_event(:info, content, :authentication, data)

      assert {:ok, message} = :gen_tcp.recv(recv, 0)

      assert message == <<?p, 40::integer-32, "md5", "ae5546ff52734a18d0277977f626946c", 0>>
    end

    test "keeps state while sending the digested md5 using secret", %{
      data: data,
      recv: recv,
      content: content
    } do
      auth = %{
        secrets: fn -> %{secret: "9e2e8a8fce0afe2d60bd8207455192cd"} end,
        method: :other
      }

      data = Map.put(data, :auth, auth)

      assert {:keep_state, ^data} = Db.handle_event(:info, content, :authentication, data)

      assert {:ok, message} = :gen_tcp.recv(recv, 0)

      assert message == <<?p, 40::integer-32, "md5", "ae5546ff52734a18d0277977f626946c", 0>>
    end
  end

  describe "handle_event/4 info tcp error" do
    test "handles server invalid auth response" do
      bin = <<?X, 4::32>>

      {_a, b} = sockpair()
      content = {:tcp, b, bin}

      assert {:stop, :auth_error, %{}} = Db.handle_event(:info, content, :authentication, %{})
    end
  end
end
