defmodule PgEdge.DbHandlerTest do
  use ExUnit.Case, async: false
  alias PgEdge.DbHandler, as: Db
  # import Mock

  describe "init/1" do
    test "starts with correct state" do
      args = %{auth: %{}, tenant: "test_tenant"}

      {:ok, :connect, data, {_, next_event, _}} = Db.init(args)
      assert next_event == :internal
      assert data.socket == nil
      assert data.caller == nil
      assert data.sent == false
      assert data.auth == args.auth
      assert data.tenant == args.tenant
      assert data.buffer == ""
      assert data.db_state == nil
      assert data.parameter_status == %{}
      assert data.state == nil
      assert data.nonce == nil
      assert data.messages == ""
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
      :meck.new(:gen_tcp, [:unstick])

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
    end
  end
end
