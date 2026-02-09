defmodule Supavisor.DbHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.DbHandler, as: Db
  alias Supavisor.Protocol.Server
  alias Supavisor.EncryptedSecrets
  alias Supavisor.ClientHandler.Auth.{PasswordSecrets, SASLSecrets, MD5Secrets}

  # import Mock
  @id {{:single, "tenant"}, "user", :transaction, "postgres", nil}

  defmodule MockDbHandler do
    use GenServer

    def start_link(behavior) do
      GenServer.start_link(__MODULE__, behavior)
    end

    def init(behavior) do
      {:ok, %{behavior: behavior, sock: {:fake_db_sock, self()}}}
    end

    def handle_call({:checkout, _sock, _caller}, _from, %{behavior: behavior} = state) do
      case behavior do
        :normal ->
          {:reply, {:ok, state.sock}, state}

        :crash ->
          raise "simulated crash"

        :normal_exit ->
          exit(:normal)

        :timeout ->
          # Don't reply to simulate timeout
          {:noreply, state}
      end
    end
  end

  defmodule FakeManager do
    use GenServer

    def start_link(config) do
      GenServer.start_link(__MODULE__, config)
    end

    def init(config) do
      # Register with the expected name
      Registry.register(Supavisor.Registry.Tenants, {:manager, config.id}, nil)
      {:ok, config}
    end

    def handle_call(:get_config, _from, state) do
      config = %{
        id: state.id,
        auth: state.auth,
        user: state.user,
        tenant: state.tenant,
        mode: state.mode,
        replica_type: state.replica_type,
        log_level: state.log_level,
        tenant_feature_flags: state.tenant_feature_flags
      }

      {:reply, config, state}
    end

    def handle_call(:get_auth, _from, state) do
      {:reply, state.auth, state}
    end

    def handle_cast({:shutdown_with_error, _error}, state) do
      {:noreply, state}
    end
  end

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
      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "user", password: "pass"})

      auth = %{secrets: encrypted_secrets}
      tenant = "test_tenant"
      user = "user"

      # Set up tenant cache for the @id
      table = :ets.new(:tenant_cache, [:set, :public])
      Registry.register(Supavisor.Registry.Tenants, {:cache, @id}, table)

      Supavisor.SecretCache.put_upstream_auth_secrets(@id, encrypted_secrets)

      manager_config = %{
        id: @id,
        auth: auth,
        tenant: {:single, tenant},
        user: user,
        mode: :transaction,
        replica_type: :single,
        log_level: nil,
        tenant_feature_flags: %{}
      }

      {:ok, _manager} = start_supervised({FakeManager, manager_config})

      args = %{id: @id}

      {:ok, :connect, data, {_, next_event, _}} = Db.init(args)
      assert next_event == :internal
      assert data.sock == nil
      assert data.caller == nil
      assert data.auth == auth
      assert data.tenant == manager_config.tenant
      assert data.db_state == nil
      assert data.parameter_status == %{}
      assert data.nonce == nil
      assert data.server_proof == nil
    end

    test "enters waiting_for_secrets state when upstream secrets are missing" do
      auth = %{host: ~c"localhost", port: 5432}
      tenant = "test_tenant"
      user = "user"

      # Set up tenant cache but don't put any secrets in it
      table = :ets.new(:tenant_cache, [:set, :public])
      Registry.register(Supavisor.Registry.Tenants, {:cache, @id}, table)

      manager_config = %{
        id: @id,
        auth: auth,
        tenant: {:single, tenant},
        user: user,
        mode: :transaction,
        replica_type: :single,
        log_level: nil,
        tenant_feature_flags: %{}
      }

      {:ok, _manager} = start_supervised({FakeManager, manager_config})

      args = %{id: @id}

      assert {:ok, :waiting_for_secrets, data} = Db.init(args)
      assert data.id == @id
      assert data.manager_ref != nil
    end

    test "transitions from waiting_for_secrets to connect when secrets become available" do
      auth = %{host: ~c"localhost", port: 5432}
      tenant = "test_tenant"
      user = "user"

      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "some user", password: "secret"})

      # Set up tenant cache
      table = :ets.new(:tenant_cache, [:set, :public])
      Registry.register(Supavisor.Registry.Tenants, {:cache, @id}, table)

      manager_config = %{
        id: @id,
        auth: auth,
        tenant: {:single, tenant},
        user: user,
        mode: :transaction,
        replica_type: :single,
        log_level: nil,
        tenant_feature_flags: %{}
      }

      {:ok, _manager} = start_supervised({FakeManager, manager_config})

      # Initialize in waiting_for_secrets state
      args = %{id: @id}
      assert {:ok, :waiting_for_secrets, data} = Db.init(args)

      # Now put secrets in cache
      Supavisor.SecretCache.put_upstream_auth_secrets(@id, encrypted_secrets)

      # Notify that secrets are available
      assert {:next_state, :connect, updated_data, {:next_event, :internal, :connect}} =
               Db.handle_event(:cast, :secrets_available, :waiting_for_secrets, data)

      assert %EncryptedSecrets{} = updated_data.auth.secrets
      assert updated_data.manager_ref == nil
    end
  end

  describe "handle_event/4" do
    test "db is available" do
      {:ok, sock} = :gen_tcp.listen(0, mode: :binary, active: false)
      {:ok, {host, port}} = :inet.sockname(sock)

      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "some user", password: "pass"})

      auth = %{
        host: host,
        port: port,
        user: "some user",
        require_user: true,
        database: "some database",
        application_name: "some application name",
        ip_version: :inet,
        secrets: encrypted_secrets
      }

      state =
        Db.handle_event(:internal, :connect, :connect, %{
          auth: auth,
          sock: {:gen_tcp, nil},
          id: @id,
          mode: :session
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
                  secrets: %EncryptedSecrets{}
                },
                sock: {:gen_tcp, _},
                id: @id,
                mode: :session
              }} = state
    end

    test "db is not available" do
      # We assume that there is nothing running on this port
      # credo:disable-for-next-line Credo.Check.Readability.LargeNumbers
      {host, port} = {{127, 0, 0, 1}, 12345}

      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "some user", password: "pass"})

      auth = %{
        id: @id,
        host: host,
        port: port,
        user: "some user",
        database: "some database",
        application_name: "some application name",
        require_user: true,
        ip_version: :inet,
        secrets: encrypted_secrets
      }

      assert {:keep_state, _data, {:state_timeout, 2_500, :connect}} =
               Db.handle_event(:internal, :connect, :connect, %{
                 auth: auth,
                 sock: nil,
                 id: @id,
                 proxy: false,
                 tenant: {:single, "some tenant"},
                 reconnect_retries: 0
               })

      assert {:stop, {:failed_to_connect, _}} =
               Db.handle_event(:internal, :connect, :connect, %{
                 auth: auth,
                 sock: nil,
                 id: @id,
                 proxy: false,
                 tenant: {:single, "some tenant"},
                 reconnect_retries: 5
               })
    end

    test "checkout returns error when in waiting_for_secrets state" do
      data = %{id: @id}
      from = {self(), make_ref()}

      expected_error = %{
        "S" => "FATAL",
        "C" => "28P01",
        "M" =>
          "Authentication credentials are invalid. Please reconnect with fresh credentials to restore pool functionality."
      }

      assert {:keep_state_and_data, {:reply, ^from, {:error, ^expected_error}}} =
               Db.handle_event(
                 {:call, from},
                 {:checkout, nil, self()},
                 :waiting_for_secrets,
                 data
               )
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

      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "some user", password: "pass"})

      auth = %{
        host: host,
        port: port,
        user: "some user",
        require_user: true,
        database: "some database",
        application_name: "some application name",
        ip_version: :inet,
        secrets: encrypted_secrets,
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

      assert {:stop, {:failed_to_connect, :ssl_not_available}} ==
               Db.handle_event(:internal, :connect, :connect, data)
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

      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "some_user", password: "some_password"})

      data = %{
        auth: %{
          user: "some_user",
          method: :password,
          secrets: encrypted_secrets
        },
        sock: {:gen_tcp, a}
      }

      assert {:keep_state, ^data} = Db.handle_event(:info, content, :authentication, data)

      assert {:ok, message} = :gen_tcp.recv(b, 0)

      password = <<"some_password", 0>>

      assert message ==
               <<?p, byte_size(password) + 4::32-big, password::binary>>
    end
  end

  describe "handle_event/4 info tcp authentication authentication_sasl_password payload events" do
    setup do
      {send, recv} = sockpair()

      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "user", password: "pass"})

      data = %{
        auth: %{
          user: "user",
          require_user: false,
          secrets: encrypted_secrets
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

      secrets = %SASLSecrets{
        user: "user",
        digest: "SCRAM-SHA-256",
        iterations: 4096,
        salt: "salt",
        client_key: :binary.copy(<<1>>, 32),
        stored_key: :binary.copy(<<2>>, 32),
        server_key: :binary.copy(<<3>>, 32)
      }

      encrypted_secrets = EncryptedSecrets.encrypt(secrets)

      data = %{
        auth: %{
          user: "user",
          secrets: encrypted_secrets,
          require_user: false,
          method: :auth_query,
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
        Server.error_message("28P01", "password authentication failed") |> IO.iodata_to_binary()

      {_a, b} = sockpair()
      content = {:tcp, b, bin}

      data = %{
        id: @id,
        mode: :session,
        user: "some user",
        client_sock: nil,
        terminating_error: nil
      }

      # Step 1: Receive error from DB, should prepare to terminate
      assert {:keep_state_and_data,
              {:next_event, :internal, {:terminate_with_error, error, :keep_pool}}} =
               Db.handle_event(:info, content, :authentication, data)

      assert error == %{
               "C" => "28P01",
               "M" => "password authentication failed",
               "S" => "FATAL",
               "V" => "FATAL"
             }

      # Step 2: Process internal event, should transition to terminating_with_error
      assert {:next_state, :terminating_with_error, new_data} =
               Db.handle_event(
                 :internal,
                 {:terminate_with_error, error, :keep_pool},
                 :authentication,
                 data
               )

      assert new_data.terminating_error == error

      # Verify the cast was sent to self
      assert_received {:"$gen_cast", :finalize_termination}

      # Step 3: Process finalize_termination cast, should stop
      assert {:stop, :normal} =
               Db.handle_event(:cast, :finalize_termination, :terminating_with_error, new_data)
    end

    test "encodes and forwards server error to client socket" do
      bin = Server.error_message("XX000", "generic error") |> IO.iodata_to_binary()
      {send, recv} = sockpair()
      content = {:tcp, recv, bin}

      data = %{
        id: @id,
        mode: :session,
        user: "some user",
        client_sock: {:gen_tcp, send},
        terminating_error: nil
      }

      # Step 1: Receive error from DB, should prepare to terminate
      assert {:keep_state_and_data,
              {:next_event, :internal, {:terminate_with_error, error, :keep_pool}}} =
               Db.handle_event(:info, content, :authentication, data)

      assert error == %{"C" => "XX000", "M" => "generic error", "S" => "FATAL", "V" => "FATAL"}

      # Step 2: Process internal event, should forward error to client and transition to terminating_with_error
      assert {:next_state, :terminating_with_error, new_data} =
               Db.handle_event(
                 :internal,
                 {:terminate_with_error, error, :keep_pool},
                 :authentication,
                 data
               )

      assert new_data.terminating_error == error

      # Verify error was sent to client socket
      expected_error_bin = Server.encode_error_message(error) |> IO.iodata_to_binary()
      assert {:ok, ^expected_error_bin} = :gen_tcp.recv(recv, 0, 1000)

      # Verify the cast was sent to self
      assert_received {:"$gen_cast", :finalize_termination}

      # Step 3: Process finalize_termination cast, should stop
      assert {:stop, :normal} =
               Db.handle_event(:cast, :finalize_termination, :terminating_with_error, new_data)
    end
  end

  describe "handle_event/4 info tcp authentication authentication_md5_password payload events" do
    setup do
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
      encrypted_secrets =
        EncryptedSecrets.encrypt(%PasswordSecrets{user: "some_user", password: "some_password"})

      auth = %{
        user: "some_user",
        method: :password,
        secrets: encrypted_secrets
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
      encrypted_secrets =
        EncryptedSecrets.encrypt(%MD5Secrets{
          user: "some_user",
          password: "9e2e8a8fce0afe2d60bd8207455192cd"
        })

      auth = %{
        secrets: encrypted_secrets,
        method: :auth_query_md5
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

  describe "checkout/4 error handling" do
    test "successful checkout" do
      {:ok, mock_pid} = start_supervised({MockDbHandler, :normal})
      dummy_sock = {:gen_tcp, self()}
      caller = self()

      assert {:ok, {:fake_db_sock, ^mock_pid}} = Db.checkout(mock_pid, dummy_sock, caller, 1000)
    end

    test "handles process crash during checkout" do
      {:ok, mock_pid} = start_supervised({MockDbHandler, :crash})
      dummy_sock = {:gen_tcp, self()}
      caller = self()

      assert {:error, {:exit, {{%RuntimeError{}, _}, _}}} =
               Db.checkout(mock_pid, dummy_sock, caller, 1000)
    end

    test "handles process normal exit during checkout" do
      {:ok, mock_pid} = start_supervised({MockDbHandler, :normal_exit})
      dummy_sock = {:gen_tcp, self()}
      caller = self()

      assert {:error, {:exit, {:normal, _}}} = Db.checkout(mock_pid, dummy_sock, caller, 1000)
    end

    test "handles checkout timeout" do
      {:ok, mock_pid} = start_supervised({MockDbHandler, :timeout})
      dummy_sock = {:gen_tcp, self()}
      caller = self()

      assert {:error, {:exit, {:timeout, _}}} = Db.checkout(mock_pid, dummy_sock, caller, 100)
    end
  end
end
