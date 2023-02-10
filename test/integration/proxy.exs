defmodule PgEdge.Integration.Proxy do
  use PgEdge.DataCase
  alias Postgrex, as: P

  @tenant "dev_tenant"

  setup_all do
    db_conf = Application.get_env(:pg_edge, Repo)

    {:ok, proxy} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: Application.get_env(:pg_edge, :proxy_port),
        database: db_conf[:database],
        password: "no_pass",
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

    %{proxy: proxy, origin: origin}
  end

  test "insert", %{proxy: proxy, origin: origin} do
    P.query(proxy, "insert into public.test (details) values ('test_insert')", [])

    assert {:ok, %P.Result{num_rows: 1}} =
             P.query(origin, "select * from public.test where details = 'test_insert'", [])
  end

  test "select", %{proxy: proxy, origin: origin} do
    P.query(origin, "insert into public.test (details) values ('test_select')", [])

    assert {:ok, %P.Result{num_rows: 1}} =
             P.query(proxy, "select * from public.test where details = 'test_select'", [])
  end

  test "update", %{proxy: proxy, origin: origin} do
    P.query(origin, "insert into public.test (details) values ('test_update')", [])

    P.query(
      proxy,
      "update public.test set details = 'test_update_updated' where details = 'test_update'",
      []
    )

    assert {:ok, %P.Result{num_rows: 1}} =
             P.query(
               origin,
               "select * from public.test where details = 'test_update_updated'",
               []
             )
  end

  test "delete", %{proxy: proxy, origin: origin} do
    P.query(origin, "insert into public.test (details) values ('test_delete')", [])
    P.query(proxy, "delete from public.test where details = 'test_delete'", [])

    assert {:ok, %P.Result{num_rows: 0}} =
             P.query(origin, "select * from public.test where details = 'test_delete'", [])
  end
end
