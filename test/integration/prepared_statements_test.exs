defmodule Supavisor.Integration.PreparedStatementsTest do
  use Supavisor.DataCase, async: false

  require Logger

  @tenant "proxy_tenant1"

  @moduletag integration: true

  @sample_query """
  SELECT schemaname, tablename, tableowner, hasindexes
  FROM pg_tables
  WHERE schemaname = $1
  ORDER BY tablename;
  """

  alias Supavisor.Protocol.PreparedStatements

  setup do
    Logger.configure(level: :error)

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
    query = Postgrex.prepare!(conn, "", @sample_query)
    assert {:ok, _, %{rows: _}} = Postgrex.execute(conn, query, ["public"])

    query = Postgrex.prepare!(conn, "", @sample_query)
    assert {:ok, _, %{rows: _}} = Postgrex.execute(conn, query, ["private"])
  end

  test "prepared statement limit (client)", %{conns: [conn | _]} do
    limit = PreparedStatements.client_limit()

    for i <- 0..(limit - 1) do
      query = Postgrex.prepare!(conn, "q_#{i}", @sample_query)
      assert {:ok, _, %{rows: _}} = Postgrex.execute(conn, query, ["public"])
    end

    assert_raise Postgrex.Error, ~r/Max prepared statements limit reached/, fn ->
      Postgrex.prepare!(conn, "q_err", @sample_query)
    end
  end

  test "prepared statement soft limit (backend)", %{conns: conns} do
    test_pid = self()
    limit = PreparedStatements.client_limit()

    for conn <- conns, i <- 0..(limit - 1) do
      query = Postgrex.prepare!(conn, "q_#{i}", @sample_query)
      assert {:ok, _, %{rows: _}} = Postgrex.execute(conn, query, ["public"])
    end

    # trick: to ensure we check all backends, we start a transaction for each,
    # so we don't get the same connection twice
    for conn <- conns do
      spawn_link(fn ->
        Postgrex.transaction(conn, fn conn ->
          assert %{rows: [[count]]} =
                   Postgrex.query!(conn, "SELECT COUNT(*) FROM pg_prepared_statements", [])

          send(test_pid, {self(), count})

          receive do
            :end -> :ok
          end
        end)
      end)
    end

    for _c <- conns do
      assert_receive {pid, count}
      assert count <= PreparedStatements.backend_limit()
      send(pid, :end)
    end
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

          query = Postgrex.prepare!(conn, name, @sample_query)

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
