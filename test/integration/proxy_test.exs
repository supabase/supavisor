defmodule Supavisor.Integration.ProxyTest do
  use Supavisor.DataCase, async: false

  require Logger

  alias Postgrex, as: P
  alias Supavisor.Support.{Cluster, SSLHelper}

  @tenants ["proxy_tenant_ps_enabled", "proxy_tenant_ps_disabled"]

  defp setup_tenant_connections(tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    assert {:ok, proxy} =
             Postgrex.start_link(
               hostname: db_conf[:hostname],
               port: Application.get_env(:supavisor, :proxy_port_transaction),
               database: db_conf[:database],
               password: db_conf[:password],
               username: db_conf[:username] <> "." <> tenant
             )

    assert {:ok, origin} =
             Postgrex.start_link(
               hostname: db_conf[:hostname],
               port: db_conf[:port],
               database: db_conf[:database],
               password: db_conf[:password],
               username: db_conf[:username]
             )

    %{db_conf: db_conf, proxy: proxy, origin: origin, user: db_conf[:username]}
  end

  for tenant <- @tenants do
    test "insert with #{tenant}" do
      %{proxy: proxy, origin: origin} = setup_tenant_connections(unquote(tenant))
      test_value = "test_insert_#{unquote(tenant)}"
      P.query!(proxy, "insert into public.test (details) values ($1)", [test_value])

      assert %P.Result{num_rows: 1} =
               P.query!(origin, "select * from public.test where details = $1", [test_value])
    end
  end

  for tenant <- @tenants do
    test "the wrong password with #{tenant}" do
      db_conf = Application.get_env(:supavisor, Repo)

      url =
        "postgresql://#{db_conf[:username] <> "." <> unquote(tenant)}:no_pass@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

      assert {:error,
              %Postgrex.Error{
                postgres: %{
                  code: :invalid_password,
                  message: "password authentication failed for user \"" <> _,
                  severity: "FATAL",
                  pg_code: "28P01"
                }
              }} = parse_uri(url) |> single_connection()
    end
  end

  for tenant <- @tenants do
    @tag cluster: true
    test "query via another node with #{tenant}" do
      %{proxy: proxy, user: user} = setup_tenant_connections(unquote(tenant))
      assert {:ok, _pid, node2} = Cluster.start_node()

      sup =
        Enum.reduce_while(1..30, nil, fn _, acc ->
          case Supavisor.get_global_sup({unquote(tenant), user, :transaction}) do
            nil ->
              Process.sleep(100)
              {:cont, acc}

            pid ->
              {:halt, pid}
          end
        end)

      assert sup ==
               :erpc.call(
                 node2,
                 Supavisor,
                 :get_global_sup,
                 [{unquote(tenant), user, :transaction}],
                 15_000
               )

      db_conf = Application.fetch_env!(:supavisor, Repo)

      assert {:ok, proxy2} =
               Postgrex.start_link(
                 hostname: db_conf[:hostname],
                 port: Application.get_env(:supavisor, :secondary_proxy_port),
                 database: db_conf[:database],
                 password: db_conf[:password],
                 username: db_conf[:username] <> "." <> unquote(tenant)
               )

      test_value = "dist_test_insert_#{unquote(tenant)}"
      P.query!(proxy2, "insert into public.test (details) values ($1)", [test_value])

      assert %P.Result{num_rows: 1} =
               P.query!(proxy, "select * from public.test where details = $1", [test_value])

      assert sup ==
               :erpc.call(
                 node2,
                 Supavisor,
                 :get_global_sup,
                 [{unquote(tenant), user, :transaction}],
                 15_000
               )
    end
  end

  for tenant <- @tenants do
    test "select with #{tenant}" do
      %{proxy: proxy, origin: origin} = setup_tenant_connections(unquote(tenant))
      test_value = "test_select_#{unquote(tenant)}"
      P.query!(origin, "insert into public.test (details) values ($1)", [test_value])

      assert %P.Result{num_rows: 1} =
               P.query!(proxy, "select * from public.test where details = $1", [test_value])
    end
  end

  for tenant <- @tenants do
    test "update with #{tenant}" do
      %{proxy: proxy, origin: origin} = setup_tenant_connections(unquote(tenant))
      test_value = "test_update_#{unquote(tenant)}"
      updated_value = "test_update_updated_#{unquote(tenant)}"
      P.query!(origin, "insert into public.test (details) values ($1)", [test_value])

      P.query!(
        proxy,
        "update public.test set details = $1 where details = $2",
        [updated_value, test_value]
      )

      assert %P.Result{num_rows: 1} =
               P.query!(
                 origin,
                 "select * from public.test where details = $1",
                 [updated_value]
               )
    end
  end

  for tenant <- @tenants do
    test "delete with #{tenant}" do
      %{proxy: proxy, origin: origin} = setup_tenant_connections(unquote(tenant))
      test_value = "test_delete_#{unquote(tenant)}"
      P.query!(origin, "insert into public.test (details) values ($1)", [test_value])
      P.query!(proxy, "delete from public.test where details = $1", [test_value])

      assert %P.Result{num_rows: 0} =
               P.query!(origin, "select * from public.test where details = $1", [test_value])
    end
  end

  test "too many clients in session mode" do
    %{db_conf: db_conf} = setup_tenant_connections(List.first(@tenants))
    port = Application.get_env(:supavisor, :proxy_port_session)

    connection_opts =
      Keyword.merge(db_conf,
        username: "max_clients.proxy_tenant1",
        port: port
      )

    assert {:ok, _} = single_connection(connection_opts)
    assert {:ok, _} = single_connection(connection_opts)

    :timer.sleep(1000)

    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message:
                  "MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size",
                unknown: "FATAL",
                severity: "FATAL",
                pg_code: "XX000"
              }
            }} = single_connection(connection_opts)
  end

  test "http to proxy server returns 200 OK" do
    assert :httpc.request(
             "http://localhost:#{Application.get_env(:supavisor, :proxy_port_transaction)}"
           ) ==
             {:ok,
              {{~c"HTTP/1.1", 204, ~c"OK"},
               [{~c"x-app-version", Application.spec(:supavisor, :vsn)}], []}}
  end

  test "checks that client_handler is idle and db_connection is nil for transaction mode" do
    %{db_conf: db_conf} = setup_tenant_connections(List.first(@tenants))

    url =
      "postgresql://transaction.proxy_tenant1:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    assert {:ok, pid} = parse_uri(url) |> single_connection()

    [{_, client_pid, _}] =
      Supavisor.get_local_manager(
        {{:single, "proxy_tenant1"}, "transaction", :transaction, "postgres", nil}
      )
      |> :sys.get_state()
      |> Access.get(:tid)
      |> :ets.tab2list()

    assert {state, map} = :sys.get_state(client_pid)
    assert %{db_connection: db_connection} = map

    assert {:idle, nil} = {state, db_connection}
    :gen_statem.stop(pid)
  end

  test "limit client connections" do
    %{db_conf: db_conf} = setup_tenant_connections(List.first(@tenants))

    connection_opts = [
      hostname: db_conf[:hostname],
      port: Application.get_env(:supavisor, :proxy_port_transaction),
      username: "max_clients.prom_tenant",
      database: "postgres",
      password: db_conf[:password]
    ]

    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message: "Max client connections reached",
                pg_code: "XX000",
                severity: "FATAL",
                unknown: "FATAL"
              }
            }} = single_connection(connection_opts)
  end

  test "change role password" do
    %{origin: origin, db_conf: db_conf} = setup_tenant_connections("is_manager")

    conn = fn pass ->
      "postgresql://dev_postgres.is_manager:#{pass}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres?sslmode=disable"
    end

    first_pass = conn.(db_conf[:password])
    new_pass = conn.("postgres_new")

    assert {:ok, first_conn} = parse_uri(first_pass) |> single_connection()

    assert [%Postgrex.Result{rows: [["1"]]}] =
             P.SimpleConnection.call(first_conn, {:query, "select 1;"})

    P.query(origin, "alter user dev_postgres with password 'postgres_new';", [])

    # First attempt with new password should fail (cache not updated yet)
    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :invalid_password,
                message: "password authentication failed for user \"" <> _,
                severity: "FATAL",
                pg_code: "28P01"
              }
            }} = parse_uri(new_pass) |> single_connection()

    # Second attempt should succeed (cache was updated by the failed attempt)
    assert {:ok, second_conn} = parse_uri(new_pass) |> single_connection()

    assert [%Postgrex.Result{rows: [["1"]]}] =
             P.SimpleConnection.call(second_conn, {:query, "select 1;"})

    # First connection should still be up: we don't terminate the pool anymore when the secrets change
    assert [%Postgrex.Result{rows: [["1"]]}] =
             P.SimpleConnection.call(first_conn, {:query, "select 1;"})

    :gen_statem.stop(first_conn)
    :gen_statem.stop(second_conn)
  end

  test "change role password for bypass user skips validation cache" do
    %{origin: origin, db_conf: db_conf} = setup_tenant_connections("is_manager")

    conn = fn pass ->
      "postgresql://bypass_user.is_manager:#{pass}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres?sslmode=disable"
    end

    first_pass = conn.(db_conf[:password])
    new_pass = conn.("postgres_new")

    assert {:ok, first_conn} = parse_uri(first_pass) |> single_connection()

    assert [%Postgrex.Result{rows: [["1"]]}] =
             P.SimpleConnection.call(first_conn, {:query, "select 1;"})

    P.query(origin, "alter user bypass_user with password 'postgres_new';", [])

    # For bypass users, first attempt with new password should succeed immediately
    # because validation secrets are not cached
    assert {:ok, second_conn} = parse_uri(new_pass) |> single_connection()

    assert [%Postgrex.Result{rows: [["1"]]}] =
             P.SimpleConnection.call(second_conn, {:query, "select 1;"})

    # First connection should still be up
    assert [%Postgrex.Result{rows: [["1"]]}] =
             P.SimpleConnection.call(first_conn, {:query, "select 1;"})

    :gen_statem.stop(first_conn)
    :gen_statem.stop(second_conn)
  end

  test "invalid characters in user or db_name" do
    %{db_conf: db_conf} = setup_tenant_connections(List.first(@tenants))

    url =
      "postgresql://user\x10user.proxy_tenant1:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres\\\\\\\\\"\\"

    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message: "Authentication error, reason: \"Invalid format for user or db_name\"",
                pg_code: "XX000",
                severity: "FATAL",
                unknown: "FATAL"
              }
            }} = parse_uri(url) |> single_connection()
  end

  defp single_connection(db_conf, c_port \\ nil) when is_list(db_conf) do
    port = c_port || db_conf[:port]

    opts = [
      hostname: db_conf[:hostname],
      port: port,
      database: db_conf[:database],
      password: db_conf[:password],
      username: db_conf[:username],
      pool_size: 1
    ]

    with {:error, {error, _}} <- start_supervised({SingleConnection, opts}) do
      {:error, error}
    end
  end

  test "connect to deleted database returns proper error" do
    %{origin: origin, db_conf: db_conf} =
      setup_tenant_connections(List.first(@tenants))

    tenant = List.first(@tenants)
    test_db = "test_db_#{:erlang.unique_integer([:positive])}"

    P.query!(origin, "CREATE DATABASE #{test_db}", [])

    assert {:ok, test_proxy} =
             Postgrex.start_link(
               hostname: db_conf[:hostname],
               port: Application.get_env(:supavisor, :proxy_port_transaction),
               database: test_db,
               password: db_conf[:password],
               username: db_conf[:username] <> "." <> tenant
             )

    assert %P.Result{rows: [[1]]} = P.query!(test_proxy, "SELECT 1", [])
    GenServer.stop(test_proxy)

    pool_sup_pid =
      Supavisor.get_global_sup(
        {{:single, tenant}, db_conf[:username], :transaction, test_db, nil}
      )

    assert is_pid(pool_sup_pid)
    assert Process.alive?(pool_sup_pid)

    P.query!(origin, "DROP DATABASE #{test_db} WITH (FORCE)", [])

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, _} =
                 single_connection(
                   hostname: db_conf[:hostname],
                   port: Application.get_env(:supavisor, :proxy_port_transaction),
                   database: test_db,
                   password: db_conf[:password],
                   username: db_conf[:username] <> "." <> tenant
                 )

        Process.sleep(200)
      end)

    assert log =~
             ~r/SingleConnection.*FATAL 3D000.*database "#{Regex.escape(test_db)}" does not exist/

    refute Process.alive?(pool_sup_pid)

    GenServer.stop(origin)
  end

  test "circuit breaker blocks get_secrets after failures" do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "circuit_breaker_secrets"

    for _ <- 1..5 do
      Supavisor.CircuitBreaker.record_failure(tenant, :get_secrets)
    end

    url =
      "postgresql://postgres.#{tenant}:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message: "Circuit breaker open: Failed to retrieve database credentials",
                pg_code: "XX000",
                severity: "FATAL",
                unknown: "FATAL"
              }
            }} = parse_uri(url) |> single_connection()

    Supavisor.CircuitBreaker.clear(tenant, :get_secrets)
  end

  test "circuit breaker blocks db_connection after failures" do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "circuit_breaker_db_conn"

    for _ <- 1..100 do
      Supavisor.CircuitBreaker.record_failure(tenant, :db_connection)
    end

    url =
      "postgresql://#{db_conf[:username]}.#{tenant}:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message:
                  "Circuit breaker open: Unable to establish connection to upstream database",
                pg_code: "XX000",
                severity: "FATAL",
                unknown: "FATAL"
              }
            }} = parse_uri(url) |> single_connection()

    Supavisor.CircuitBreaker.clear(tenant, :db_connection)
  end

  test "circuit breaker blocks auth after 10 failed password attempts" do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "circuit_breaker_auth"

    url =
      "postgresql://#{db_conf[:username]}.#{tenant}:wrong_password@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    # First 10 attempts should fail with authentication error
    for _ <- 1..10 do
      assert {:error,
              %Postgrex.Error{
                postgres: %{
                  code: :invalid_password,
                  message: "password authentication failed for user \"" <> _,
                  severity: "FATAL",
                  pg_code: "28P01"
                }
              }} = parse_uri(url) |> single_connection()
    end

    # 11th attempt should fail with circuit breaker error
    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message: "Circuit breaker open: Too many authentication errors",
                pg_code: "XX000",
                severity: "FATAL",
                unknown: "FATAL"
              }
            }} = parse_uri(url) |> single_connection()

    # Clean up - clear circuit breaker for this tenant+IP
    Supavisor.CircuitBreaker.clear({tenant, "127.0.0.1"}, :auth_error)
  end

  test "handles fatal TLS alert by terminating connection" do
    # Setup SSL certificates for testing
    {:ok, _cert_path, _key_path} = SSLHelper.configure_test_ssl()

    # Save original SSL config to restore later
    original_cert = Application.get_env(:supavisor, :global_downstream_cert)
    original_key = Application.get_env(:supavisor, :global_downstream_key)

    on_exit(fn ->
      # Restore original SSL configuration
      Application.put_env(:supavisor, :global_downstream_cert, original_cert)
      Application.put_env(:supavisor, :global_downstream_key, original_key)
    end)

    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = List.first(@tenants)
    port = Application.get_env(:supavisor, :proxy_port_transaction)

    # Establish an SSL connection at the socket level
    {:ok, tcp_socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

    # Send SSL request message
    ssl_request = <<8::32, 80_877_103::32>>
    :ok = :gen_tcp.send(tcp_socket, ssl_request)

    # Server should respond with 'S' for SSL support
    {:ok, <<"S">>} = :gen_tcp.recv(tcp_socket, 1, 5000)

    # Upgrade to SSL
    {:ok, ssl_socket} =
      :ssl.connect(tcp_socket, [verify: :verify_none, active: false], 5000)

    # Send startup message with authentication
    username = db_conf[:username] <> "." <> tenant
    database = db_conf[:database]

    startup_params = [
      {"user", username},
      {"database", database}
    ]

    startup_message =
      IO.iodata_to_binary([
        for {key, value} <- startup_params do
          [key, 0, value, 0]
        end,
        0
      ])

    packet = <<byte_size(startup_message) + 8::32, 196_608::32, startup_message::binary>>
    :ok = :ssl.send(ssl_socket, packet)

    # Receive authentication challenge
    {:ok, _auth_response} = :ssl.recv(ssl_socket, 0, 5000)

    # Get underlying TCP socket and send malformed data to trigger a FATAL alert from server
    {:sslsocket, {:gen_tcp, tcp_port, _tls_sender, _opts}, _pids} = ssl_socket

    # Send garbage data directly to TCP socket to corrupt the TLS stream
    # This will cause the server to send a FATAL alert (Bad Record MAC or Decode Error)
    garbage = :crypto.strong_rand_bytes(100)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        :gen_tcp.send(tcp_port, garbage)
        # Give time for server to process and send FATAL alert back
        Process.sleep(500)
      end)

    # Check that we logged the fatal TLS alert and terminated
    # The server will generate a FATAL alert in response to the corrupted data
    assert log =~ "Received fatal TLS alert"
    assert log =~ "terminating connection"
  end

  test "no warm pool user has empty pool after disconnect in session mode" do
    %{db_conf: db_conf} = setup_tenant_connections(List.first(@tenants))

    connection_opts = [
      hostname: db_conf[:hostname],
      port: Application.get_env(:supavisor, :proxy_port_session),
      database: db_conf[:database],
      password: db_conf[:password],
      username: "no_warm_pool_user.proxy_tenant1"
    ]

    # Connect and execute a query
    assert {:ok, conn} = single_connection(connection_opts)
    assert [%P.Result{rows: [["1"]]}] = P.SimpleConnection.call(conn, {:query, "select 1;"})

    tenant_id =
      {{:single, "proxy_tenant1"}, "no_warm_pool_user", :session, db_conf[:database], nil}

    # Pool should have workers while connected
    assert count_pool_workers(tenant_id) > 0

    # Disconnect
    :gen_statem.stop(conn)
    Process.sleep(100)

    # For no_warm_pool_user, pool should be empty after disconnect
    assert count_pool_workers(tenant_id) == 0
  end

  defp count_pool_workers(tenant_id) do
    tenant_id
    |> Supavisor.get_global_sup()
    |> get_poolboy_workers()
    |> length()
  end

  defp get_poolboy_workers(tenant_sup) do
    tenant_sup
    |> Supervisor.which_children()
    |> Enum.filter(&match?({:pool, _}, elem(&1, 0)))
    |> Enum.flat_map(fn {_id, pool_pid, _type, _modules} ->
      pool_pid
      |> Process.info()
      |> Kernel.get_in([:links])
      |> Enum.find(&poolboy_supervisor?/1)
      |> case do
        nil -> []
        poolboy_sup -> Supervisor.which_children(poolboy_sup)
      end
      |> Enum.filter(&is_pid(elem(&1, 1)))
    end)
  end

  defp poolboy_supervisor?(pid) do
    case Process.info(pid)[:dictionary][:"$initial_call"] do
      {:supervisor, :poolboy_sup, _} -> true
      _ -> false
    end
  end

  defp parse_uri(uri) do
    %URI{
      userinfo: userinfo,
      host: host,
      port: port,
      path: path
    } = URI.parse(uri)

    [username, pass] = String.split(userinfo, ":")
    database = String.replace(path, "/", "")

    [hostname: host, port: port, database: database, password: pass, username: username]
  end
end
