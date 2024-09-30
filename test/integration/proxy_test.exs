defmodule Supavisor.Integration.ProxyTest do
  use Supavisor.DataCase, async: true

  require Logger

  alias Postgrex, as: P
  alias Supavisor.Support.Cluster

  @tenant "proxy_tenant1"

  setup do
    db_conf = Application.get_env(:supavisor, Repo)

    {:ok, proxy} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: Application.get_env(:supavisor, :proxy_port_transaction),
        database: db_conf[:database],
        password: db_conf[:password],
        username: db_conf[:username] <> "." <> @tenant
      )

    {:ok, origin} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: db_conf[:port],
        database: db_conf[:database],
        password: db_conf[:password],
        username: db_conf[:username]
      )

    %{proxy: proxy, origin: origin, user: db_conf[:username]}
  end

  test "prepared statement", %{proxy: proxy} do
    prepare_sql =
      "PREPARE tenant (text) AS SELECT id, external_id FROM _supavisor.tenants WHERE external_id = $1;"

    db_conf = Application.get_env(:supavisor, Repo)

    {:ok, pid} =
      Keyword.merge(db_conf, username: db_conf[:username] <> "." <> @tenant)
      |> single_connection(Application.get_env(:supavisor, :proxy_port_transaction))

    assert [%Postgrex.Result{command: :prepare}] =
             P.SimpleConnection.call(pid, {:query, prepare_sql})

    :timer.sleep(500)

    assert {_, %Postgrex.Result{command: :select}} =
             Postgrex.query(proxy, "EXECUTE tenant('#{@tenant}');", [])

    :gen_statem.stop(pid)
  end

  test "the wrong password" do
    Process.flag(:trap_exit, true)
    db_conf = Application.get_env(:supavisor, Repo)

    url =
      "postgresql://#{db_conf[:username] <> "." <> @tenant}:no_pass@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    assert {:error,
            %Postgrex.Error{
              message: "error received in SCRAM server final message: \"Wrong password\""
            }} = parse_uri(url) |> single_connection()
  end

  test "insert", %{proxy: proxy, origin: origin} do
    P.query!(proxy, "insert into public.test (details) values ('test_insert')", [])

    assert %P.Result{num_rows: 1} =
             P.query!(origin, "select * from public.test where details = 'test_insert'", [])
  end

  test "query via another node", %{proxy: proxy, user: user} do
    {:ok, _pid, node2} = Cluster.start_node()

    sup =
      Enum.reduce_while(1..30, nil, fn _, acc ->
        case Supavisor.get_global_sup({@tenant, user, :transaction}) do
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
               [{@tenant, user, :transaction}],
               15_000
             )

    db_conf = Application.fetch_env!(:supavisor, Repo)

    {:ok, proxy2} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: Application.get_env(:supavisor, :secondary_proxy_port),
        database: db_conf[:database],
        password: db_conf[:password],
        username: db_conf[:username] <> "." <> @tenant
      )

    P.query!(proxy2, "insert into public.test (details) values ('dist_test_insert')", [])

    assert %P.Result{num_rows: 1} =
             P.query!(proxy, "select * from public.test where details = 'dist_test_insert'", [])

    assert sup ==
             :erpc.call(
               node2,
               Supavisor,
               :get_global_sup,
               [{@tenant, user, :transaction}],
               15_000
             )
  end

  test "select", %{proxy: proxy, origin: origin} do
    P.query!(origin, "insert into public.test (details) values ('test_select')", [])

    assert %P.Result{num_rows: 1} =
             P.query!(proxy, "select * from public.test where details = 'test_select'", [])
  end

  test "update", %{proxy: proxy, origin: origin} do
    P.query!(origin, "insert into public.test (details) values ('test_update')", [])

    P.query!(
      proxy,
      "update public.test set details = 'test_update_updated' where details = 'test_update'",
      []
    )

    assert %P.Result{num_rows: 1} =
             P.query!(
               origin,
               "select * from public.test where details = 'test_update_updated'",
               []
             )
  end

  test "delete", %{proxy: proxy, origin: origin} do
    P.query!(origin, "insert into public.test (details) values ('test_delete')", [])
    P.query!(proxy, "delete from public.test where details = 'test_delete'", [])

    assert %P.Result{num_rows: 0} =
             P.query!(origin, "select * from public.test where details = 'test_delete'", [])
  end

  test "too many clients in session mode" do
    Process.flag(:trap_exit, true)
    db_conf = Application.get_env(:supavisor, Repo)
    port = Application.get_env(:supavisor, :proxy_port_session)

    connection_opts =
      Keyword.merge(db_conf,
        username: "max_clients.proxy_tenant1",
        port: port
      )

    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message: "Max client connections reached",
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

  test "checks that client_handler is idle and db_pid is nil for transaction mode" do
    db_conf = Application.get_env(:supavisor, Repo)

    url =
      "postgresql://transaction.#{@tenant}:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    {:ok, pid} = parse_uri(url) |> single_connection()

    [{_, client_pid, _}] =
      Supavisor.get_local_manager(
        {{:single, @tenant}, "transaction", :transaction, "postgres", nil}
      )
      |> :sys.get_state()
      |> Access.get(:tid)
      |> :ets.tab2list()

    assert {state, map} = :sys.get_state(client_pid)
    assert %{db_pid: db_pid} = map

    assert {:idle, nil} = {state, db_pid}
    :gen_statem.stop(pid)
  end

  test "limit client connections" do
    Process.flag(:trap_exit, true)
    db_conf = Application.get_env(:supavisor, Repo)

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

  test "change role password", %{origin: origin} do
    Process.flag(:trap_exit, true)
    db_conf = Application.get_env(:supavisor, Repo)

    conn = fn pass ->
      "postgresql://dev_postgres.is_manager:#{pass}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres?sslmode=disable"
    end

    first_pass = conn.("postgres")
    new_pass = conn.("postgres_new")

    assert {:ok, pid} = parse_uri(first_pass) |> single_connection()

    assert [%Postgrex.Result{rows: [["1"]]}] = P.SimpleConnection.call(pid, {:query, "select 1;"})
    :gen_statem.stop(pid)
    P.query(origin, "alter user dev_postgres with password 'postgres_new';", [])
    Supavisor.stop({{:single, "is_manager"}, "dev_postgres", :transaction, "postgres"})

    :timer.sleep(1000)

    assert {:error,
            %Postgrex.Error{
              message: "error received in SCRAM server final message: \"Wrong password\""
            }} = parse_uri(new_pass) |> single_connection()

    {:ok, pid} = parse_uri(new_pass) |> single_connection()
    assert [%Postgrex.Result{rows: [["1"]]}] = P.SimpleConnection.call(pid, {:query, "select 1;"})
    :gen_statem.stop(pid)
  end

  test "invalid characters in user or db_name" do
    Process.flag(:trap_exit, true)
    db_conf = Application.get_env(:supavisor, Repo)

    url =
      "postgresql://user\"user.#{@tenant}:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres\\\\\\\\\"\\"

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

  test "max_pools limit" do
    Process.flag(:trap_exit, true)
    db_conf = Application.get_env(:supavisor, Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)

    tenant = "max_pool_tenant"

    {:ok, pid1} =
      Keyword.merge(db_conf,
        username: "postgres.#{tenant}",
        port: port
      )
      |> single_connection()

    assert Supavisor.count_pools(tenant) == 1

    {:ok, pid2} =
      Keyword.merge(db_conf,
        username: "session.#{tenant}",
        port: port
      )
      |> single_connection()

    assert Supavisor.count_pools(tenant) == 2

    {:ok, pid3} =
      Keyword.merge(db_conf,
        username: "transaction.#{tenant}",
        port: port
      )
      |> single_connection()

    assert Supavisor.count_pools(tenant) == 3

    connection_opts =
      Keyword.merge(db_conf,
        username: "max_clients.#{tenant}",
        port: port
      )

    assert {:error,
            %Postgrex.Error{
              postgres: %{
                code: :internal_error,
                message: "Max pools count reached",
                unknown: "FATAL",
                severity: "FATAL",
                pg_code: "XX000"
              }
            }} = single_connection(connection_opts)

    for pid <- [pid1, pid2, pid3], do: :gen_statem.stop(pid)
  end

  test "active_count doesn't block" do
    Process.flag(:trap_exit, true)
    db_conf = Application.get_env(:supavisor, Repo)
    port = Application.get_env(:supavisor, :proxy_port_session)

    connection_opts =
      Keyword.merge(db_conf,
        username: db_conf[:username] <> "." <> @tenant,
        port: port
      )

    assert {:ok, pid} = single_connection(connection_opts)

    id = {{:single, @tenant}, db_conf[:username], :session, db_conf[:database], nil}
    [{client_pid, _}] = Registry.lookup(Supavisor.Registry.TenantClients, id)

    assert match?({_, %{active_count: 1}}, :sys.get_state(client_pid))

    Enum.each(0..200, fn _ ->
      P.SimpleConnection.call(pid, {:query, "select 1;"})
    end)

    assert match?(
             [
               %Postgrex.Result{
                 command: :select
               }
             ],
             P.SimpleConnection.call(pid, {:query, "select 1;"})
           )
  end

  defp single_connection(db_conf, c_port \\ nil) when is_list(db_conf) do
    port = c_port || db_conf[:port]

    [
      hostname: db_conf[:hostname],
      port: port,
      database: db_conf[:database],
      password: db_conf[:password],
      username: db_conf[:username],
      pool_size: 1
    ]
    |> SingleConnection.connect()
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
