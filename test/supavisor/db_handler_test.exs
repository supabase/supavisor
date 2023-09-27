defmodule Supavisor.DbHandlerTest do
  use ExUnit.Case, async: false
  alias Supavisor.DbHandler, as: Db
  # import Mock

  describe "init/1" do
    test "starts with correct state" do
      args = %{
        id: {"a", "b"},
        auth: %{},
        tenant: "test_tenant",
        user_alias: "test_user_alias",
        user: "user",
        mode: :transaction,
        replica_type: :single
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
    test "db is avaible" do
      :meck.new(:gen_tcp, [:unstick, :passthrough])
      :meck.new(:inet, [:unstick, :passthrough])
      :meck.expect(:gen_tcp, :connect, fn _host, _port, _sock_opts -> {:ok, :sock} end)
      :meck.expect(:gen_tcp, :send, fn _sock, _msg -> :ok end)
      :meck.expect(:inet, :setopts, fn _sock, _opts -> :ok end)

      secrets = fn -> %{user: "some user", db_user: "some user"} end

      auth = %{
        host: "host",
        port: 0,
        user: "some user",
        require_user: true,
        database: "some database",
        application_name: "some application name",
        ip_version: :inet,
        secrets: secrets
      }

      state = Db.handle_event(:internal, nil, :connect, %{auth: auth, sock: {:gen_tcp, nil}})

      assert state ==
               {:next_state, :authentication,
                %{
                  auth: %{
                    application_name: "some application name",
                    database: "some database",
                    host: "host",
                    port: 0,
                    user: "some user",
                    require_user: true,
                    ip_version: :inet,
                    secrets: secrets
                  },
                  sock: {:gen_tcp, :sock}
                }}

      :meck.unload(:gen_tcp)
    end

    test "db is not avaible" do
      :meck.new(:gen_tcp, [:unstick, :passthrough])

      :meck.expect(:gen_tcp, :connect, fn _host, _port, _sock_opts -> {:error, "some error"} end)

      auth = %{
        host: "host",
        port: 0,
        user: "some user",
        database: "some database",
        application_name: "some application name",
        ip_version: :inet
      }

      state = Db.handle_event(:internal, nil, :connect, %{auth: auth, sock: nil})

      assert state == {:keep_state_and_data, {:state_timeout, 2_500, :connect}}
      :meck.unload(:gen_tcp)
    end
  end

  test "handle_event/4 with idle state" do
    {:ok, sock} = :gen_tcp.listen(0, [])
    data = %{sock: {:gen_tcp, sock}, caller: nil, buffer: []}
    from = {self(), :test_ref}
    event = {:call, from}
    payload = {:db_call, "test_data"}

    {:keep_state, new_data, reply} = Db.handle_event(event, payload, :idle, data)

    # check if the message arrived in gen_tcp.send
    assert {:reply, ^from, {:error, :enotconn}} = reply
    assert new_data.caller == self()
  end

  test "handle_event/4 with non-idle state" do
    data = %{sock: nil, caller: nil, buffer: []}
    from = {self(), :test_ref}
    event = {:call, from}
    payload = {:db_call, "test_data"}
    state = :non_idle

    {:keep_state, new_data, reply} = Db.handle_event(event, payload, state, data)

    assert {:reply, ^from, {:buffering, 9}} = reply
    assert new_data.caller == self()
    assert new_data.buffer == ["test_data"]
  end

  describe "handle_event/4 info tcp authentication authentication_md5_password payload events" do
    test "keeps state while sending the digested md5" do
      # `82` is `?R`, which identifies the payload tag as `:authentication`
      # `0, 0, 0, 12` is the packet length
      # `0, 0, 0, 5` is the authentication type, identified as `:authentication_md5_password`
      # `100, 100, 100, 100` is the md5 salt from db, a random 4 bytes value
      bin = <<82, 0, 0, 0, 12, 0, 0, 0, 5, 100, 100, 100, 100>>

      # The incoming port (#Port<0.00>), unused
      tcp_port = Enum.random(1..999_999)

      content = {:tcp, tcp_port, bin}

      # The outgoing port (#Port<0.00>), used to send message to the db, meck overrides it
      sock_port = Enum.random(1..999_999)

      data = %{
        auth: %{
          password: fn -> "some_password" end,
          user: "some_user"
        },
        sock: {:gen_tcp, sock_port}
      }

      :meck.new(:gen_tcp, [:unstick, :passthrough])

      :meck.expect(:gen_tcp, :send, fn port, message ->
        assert port == sock_port
        assert message == [?p, <<40::integer-32>>, ["md5", "ae5546ff52734a18d0277977f626946c", 0]]

        :ok
      end)

      assert {:keep_state, ^data} = Db.handle_event(:info, content, :authentication, data)

      :meck.unload(:gen_tcp)
    end
  end
end
