defmodule Supavisor.DbHandlerTest do
  use ExUnit.Case, async: false
  alias Supavisor.DbHandler, as: Db
  # import Mock

  describe "init/1" do
    test "starts with correct state" do
      args = %{auth: %{}, tenant: "test_tenant", user_alias: "test_user_alias"}

      {:ok, :connect, data, {_, next_event, _}} = Db.init(args)
      assert next_event == :internal
      assert data.socket == nil
      assert data.caller == nil
      assert data.sent == false
      assert data.auth == args.auth
      assert data.tenant == args.tenant
      assert data.user_alias == args.user_alias
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
      :meck.expect(:gen_tcp, :connect, fn _host, _port, _socket_opts -> {:ok, :socket} end)
      :meck.expect(:gen_tcp, :send, fn _socket, _msg -> :ok end)

      auth = %{
        host: "host",
        port: 0,
        user: "some user",
        database: "some database",
        application_name: "some application name"
      }

      state = Db.handle_event(:internal, nil, :connect, %{auth: auth, socket: nil})

      assert state ==
               {:next_state, :authentication,
                %{
                  auth: %{
                    application_name: "some application name",
                    database: "some database",
                    host: "host",
                    port: 0,
                    user: "some user"
                  },
                  socket: :socket
                }}

      :meck.unload(:gen_tcp)
    end

    test "db is not avaible" do
      :meck.new(:gen_tcp, [:unstick, :passthrough])

      :meck.expect(:gen_tcp, :connect, fn _host, _port, _socket_opts -> {:error, "some error"} end)

      auth = %{
        host: "host",
        port: 0,
        user: "some user",
        database: "some database",
        application_name: "some application name"
      }

      state = Db.handle_event(:internal, nil, :connect, %{auth: auth, socket: nil})

      assert state == {:keep_state_and_data, {:state_timeout, 2_500, :connect}}
      :meck.unload(:gen_tcp)
    end
  end

  test "handle_event/4 with idle state" do
    {:ok, socket} = :gen_tcp.listen(0, [])
    data = %{socket: socket, caller: nil, buffer: []}
    from = {self(), :test_ref}
    event = {:call, from}
    payload = {:db_call, "test_data"}

    {:keep_state, new_data, reply} = Db.handle_event(event, payload, :idle, data)

    # check if the message arrived in gen_tcp.send
    assert {:reply, ^from, {:error, :enotconn}} = reply
    assert new_data.caller == self()
  end

  test "handle_event/4 with non-idle state" do
    data = %{socket: nil, caller: nil, buffer: []}
    from = {self(), :test_ref}
    event = {:call, from}
    payload = {:db_call, "test_data"}
    state = :non_idle

    {:keep_state, new_data, reply} = Db.handle_event(event, payload, state, data)

    assert {:reply, ^from, {:buffering, 9}} = reply
    assert new_data.caller == self()
    assert new_data.buffer == ["test_data"]
  end
end
