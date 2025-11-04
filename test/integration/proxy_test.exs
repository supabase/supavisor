defmodule Supavisor.Integration.ProxyTest do
  use Supavisor.DataCase, async: false

  require Logger

  alias Postgrex, as: P
  alias Supavisor.Support.Cluster

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

  test "try old password after password change" do
    %{origin: origin, db_conf: db_conf} = setup_tenant_connections(List.first(@tenants))

    try do
      old_pass =
        "postgresql://dev_postgres.is_manager:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres?sslmode=disable"

      P.query(origin, "alter user dev_postgres with password 'postgres_new';", [])

      assert {:error, %Postgrex.Error{postgres: %{code: :invalid_password}}} =
               parse_uri(old_pass) |> single_connection()
    after
      P.query(origin, "alter user dev_postgres with password '#{db_conf[:password]}';", [])
    end
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
