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
        reconnect_retries: 5
      }

      {:ok, :connect, data, {_, next_event, _}} = Db.init(args)
      assert next_event == :internal
      assert data.sock == nil
      assert data.caller == nil
      assert data.sent == false
      assert data.auth == args.auth
      assert data.tenant == args.tenant
      assert data.buffer == []
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

  describe "handle_event/4 info tcp authentication authentication_md5_password payload events" do
    test "keeps state while sending the digested md5" do
      # `82` is `?R`, which identifies the payload tag as `:authentication`
      # `0, 0, 0, 12` is the packet length
      # `0, 0, 0, 5` is the authentication type, identified as `:authentication_md5_password`
      # `100, 100, 100, 100` is the md5 salt from db, a random 4 bytes value
      bin = <<82, 0, 0, 0, 12, 0, 0, 0, 5, 100, 100, 100, 100>>

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

      assert message == <<?p, 40::integer-32, "md5", "ae5546ff52734a18d0277977f626946c", 0>>
    end
  end

  describe "check_ready/1" do
    test "ready_for_query valid" do
      assert {:ready_for_query, :transaction_block} == Db.check_ready(<<90, 0, 0, 0, 5, ?T>>)

      assert {:ready_for_query, :transaction_block} ==
               Db.check_ready(<<1, 1, 1, 90, 0, 0, 0, 5, ?T>>)

      assert {:ready_for_query, :failed_transaction_block} ==
               Db.check_ready(<<90, 0, 0, 0, 5, ?E>>)

      assert {:ready_for_query, :failed_transaction_block} ==
               Db.check_ready(<<1, 1, 1, 90, 0, 0, 0, 5, ?E>>)

      assert {:ready_for_query, :idle} == Db.check_ready(<<90, 0, 0, 0, 5, ?I>>)

      assert {:ready_for_query, :idle} ==
               Db.check_ready(<<1, 1, 1, 90, 0, 0, 0, 5, ?I>>)
    end

    test "ready_for_query not valid" do
      assert :continue == Db.check_ready(<<>>)
      assert :continue == Db.check_ready(<<90, 0, 0, 0, 5, ?I, 1, 1, 1>>)
      assert :continue == Db.check_ready(<<1, 1, 1, 90, 0, 0, 0, 5, ?I, 1, 1, 1>>)
    end
  end
end
