defmodule Supavisor.Integration.PreparedStatementsTest do
  use Supavisor.DataCase, async: false

  require Logger

  @tenant "proxy_tenant1"

  @moduletag integration: true

  setup do
    db_conf = Application.get_env(:supavisor, Repo)

    conns =
      for _i <- 1..10 do
        {:ok, conn} =
          Postgrex.start_link(
            hostname: db_conf[:hostname],
            port: Application.get_env(:supavisor, :proxy_port_transaction),
            database: db_conf[:database],
            password: db_conf[:password],
            username: db_conf[:username] <> "." <> @tenant
          )

        conn
      end

    {:ok, %{conns: conns}}
  end

  test "prepare unnamed", %{conns: [conn | _]} do
    query =
      Postgrex.prepare!(conn, "", """
      SELECT schemaname, tablename, tableowner, hasindexes
      FROM pg_tables
      WHERE schemaname = $1
      ORDER BY tablename;
      """)

    assert {:ok, _, %{rows: _}} = Postgrex.execute(conn, query, ["public"])

    query =
      Postgrex.prepare!(conn, "", """
      SELECT schemaname, tablename, tableowner, hasindexes
      FROM pg_tables
      WHERE schemaname = $1
      ORDER BY tablename;
      """)

    assert {:ok, _, %{rows: _}} = Postgrex.execute(conn, query, ["private"])
  end

  test "prepare once, run twice (concurrent processes)", %{conns: conns} do
    test_pid = self()
    process_count = 200

    processes =
      for _ <- 0..process_count do
        conn = Enum.random(conns)

        spawn_link(fn ->
          name =
            :crypto.strong_rand_bytes(16)
            |> Base.encode16(case: :lower)

          receive do
            :q1 -> :ok
          end

          query =
            Postgrex.prepare!(conn, name, """
            SELECT schemaname, tablename, tableowner, hasindexes
            FROM pg_tables
            WHERE schemaname = $1
            ORDER BY tablename;
            """)

          assert {:ok, q1, %{rows: _}} =
                   Postgrex.execute(conn, query, ["public"])

          assert q1.ref == query.ref

          receive do
            :q2 -> :ok
          end

          assert {:ok, q2, %{rows: _}} = Postgrex.execute(conn, query, ["private"])
          assert q2.ref == query.ref
          send(test_pid, :done)
        end)
      end

    for p <- processes do
      send(p, :q1)
    end

    for p <- processes do
      send(p, :q2)
    end

    for _ <- 1..process_count do
      assert_receive :done, 1000
    end
  end
end
