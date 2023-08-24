defmodule Supavisor.Integration.ProxyTest do
  use Supavisor.DataCase
  alias Postgrex, as: P

  @tenant "proxy_tenant"

  setup_all do
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

  test "the wrong password" do
    db_conf = Application.get_env(:supavisor, Repo)

    url =
      "postgresql://#{db_conf[:username] <> "." <> @tenant}:no_pass@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    {result, _} = System.cmd("psql", [url], stderr_to_stdout: true)
    assert result =~ "error received from server in SCRAM exchange: Wrong password"
  end

  test "insert", %{proxy: proxy, origin: origin} do
    P.query!(proxy, "insert into public.test (details) values ('test_insert')", [])

    assert %P.Result{num_rows: 1} =
             P.query!(origin, "select * from public.test where details = 'test_insert'", [])
  end

  test "query via another node", %{proxy: proxy, user: user} do
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
               :"secondary@127.0.0.1",
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
               :"secondary@127.0.0.1",
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

  # test "too many clients in session mode" do
  #   db_conf = Application.get_env(:supavisor, Repo)

  #   url =
  #     "postgresql://session.proxy_tenant:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port)}/postgres"

  #   spawn(fn -> System.cmd("psql", [url], stderr_to_stdout: true) end)

  #   :timer.sleep(500)

  #   {result, _} = System.cmd("psql", [url], stderr_to_stdout: true)
  #   assert result =~ "FATAL:  Too many clients already"
  # end

  test "http to proxy server returns 200 OK" do
    assert :httpc.request(
             "http://localhost:#{Application.get_env(:supavisor, :proxy_port_transaction)}"
           ) ==
             {:ok, {{'HTTP/1.1', 204, 'OK'}, [], []}}
  end

  test "checks that client_hanlder is idle and db_pid is nil for transaction mode" do
    db_conf = Application.get_env(:supavisor, Repo)

    url =
      "postgresql://transaction.proxy_tenant:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres"

    psql_pid = spawn(fn -> System.cmd("psql", [url]) end)

    :timer.sleep(500)

    [{_, client_pid, _}] =
      Supavisor.get_local_manager({"proxy_tenant", "transaction", :transaction})
      |> :sys.get_state()
      |> then(& &1[:tid])
      |> :ets.tab2list()

    {state, %{db_pid: db_pid}} = :sys.get_state(client_pid)
    :timer.sleep(500)

    assert {:idle, nil} = {state, db_pid}
    Process.exit(psql_pid, :kill)
  end

  # test "limit client connections" do
  #   db_conf = Application.get_env(:supavisor, Repo)

  #   url =
  #     "postgresql://max_clients.proxy_tenant:#{db_conf[:password]}@#{db_conf[:hostname]}:#{Application.get_env(:supavisor, :proxy_port_transaction)}/postgres?sslmode=disable"

  #   {result, _} = System.cmd("psql", [url], stderr_to_stdout: true)
  #   assert result =~ "FATAL:  Max client connections reached"
  # end
end
