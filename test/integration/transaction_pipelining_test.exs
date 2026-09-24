defmodule Supavisor.Integration.TransactionPipeliningTest do
  # Drives transaction mode with raw protocol messages and checks both what the
  # client receives and that the backend returns to the pool once, and only once,
  # Postgres is done with everything the client sent.
  use Supavisor.DataCase, async: false

  import Supavisor.Asserts

  require Supavisor

  alias Supavisor.Support.ProtocolClient

  @moduletag :integration

  @sync <<?S, 4::32>>
  @flush <<?H, 4::32>>
  @copy_done <<?c, 4::32>>

  # Each test gets its own tenant, and so its own pool.
  setup ctx do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant = "pipelining_#{System.unique_integer([:positive])}"

    {:ok, _} =
      Supavisor.Tenants.create_tenant(%{
        db_host: db_conf[:hostname],
        db_port: db_conf[:port],
        db_database: db_conf[:database],
        default_parameter_status: %{},
        external_id: tenant,
        require_user: true,
        feature_flags: %{
          "named_prepared_statements" => Map.get(ctx, :named_prepared_statements, false)
        },
        users: [
          %{
            "db_user" => db_conf[:username],
            "db_password" => db_conf[:password],
            "pool_size" => 9,
            "max_clients" => 100,
            "mode_type" => "transaction"
          }
        ]
      })

    on_exit(fn ->
      Supavisor.stop(
        Supavisor.id(type: :single, tenant: tenant, user: db_conf[:username], mode: :transaction)
      )
    end)

    {:ok, tenant: tenant}
  end

  for {label, named_prepared_statements?} <- [
        {"prepared statements disabled", false},
        {"prepared statements enabled", true}
      ] do
    describe label do
      @describetag named_prepared_statements: named_prepared_statements?

      test "delivers every reply in a pipelined batch", %{tenant: tenant} do
        sock = connect(tenant)
        n = 50

        # Fire N simple queries in a single write so they pipeline.
        :ok = :gen_tcp.send(sock, pipeline(n))

        assert recv_ready_for_queries(sock, n) == n
      end

      test "releases and reuses the backend after a pipelined batch", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, pipeline(5))
        assert recv_ready_for_queries(sock, 5) == 5

        # A fresh query on the same client connection must still succeed.
        :ok = :gen_tcp.send(sock, :pgo_protocol.encode_query_message("SELECT 1"))
        assert recv_ready_for_queries(sock, 1) == 1
      end

      test "regression: delivers every reply when a segment begins with a Sync", %{tenant: tenant} do
        sock = connect(tenant)

        # The slow query keeps the ClientHandler busy when the next write arrives.
        :ok = :gen_tcp.send(sock, :pgo_protocol.encode_query_message("SELECT pg_sleep(0.3)"))
        Process.sleep(50)

        # A write starting with a Sync must not end the batch early: the query after
        # it still has to be answered on this backend.
        :ok =
          :gen_tcp.send(sock, [
            <<?S, 4::32>>,
            :pgo_protocol.encode_query_message("SELECT pg_sleep(0.3)")
          ])

        # Both statements and the bare Sync each produce a ReadyForQuery.
        assert recv_ready_for_queries(sock, 3) == 3
      end

      test "does not fabricate a ReadyForQuery for an Execute sent without its Sync", %{
        tenant: tenant
      } do
        sock = connect(tenant)
        marker = "batch#{System.unique_integer([:positive])}"

        # Both batches land in one read: batch A ends in a Sync, batch B doesn't.
        :ok =
          :gen_tcp.send(sock, [
            extended_batch("select '#{marker}A' as m, pg_sleep(0.2)", sync?: true),
            extended_batch("select '#{marker}B' as m, pg_sleep(0.2)", sync?: false)
          ])

        # Only batch A is answered, since batch B has no Sync yet.
        assert recv_ready_for_queries(sock, 1) == 1

        db_conf = Application.get_env(:supavisor, Supavisor.Repo)

        {:ok, observer} =
          Postgrex.start_link(
            hostname: db_conf[:hostname],
            port: db_conf[:port],
            database: db_conf[:database],
            username: db_conf[:username],
            password: db_conf[:password]
          )

        Process.sleep(300)

        # The backend waits for batch B's Sync, as it should.
        assert stranded?(observer, marker <> "B")

        # Sent alone in a later write, the Sync must reach that same backend.
        :ok = :gen_tcp.send(sock, :pgo_protocol.encode_sync_message())
        assert recv_ready_for_queries(sock, 1) == 1
        Process.sleep(200)

        refute stranded?(observer, marker <> "B"),
               "backend still stranded after its withheld Sync was sent -- fabricated ReadyForQuery"

        GenServer.stop(observer)
      end

      test "answers a Sync pipelined with a query while idle", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, [@sync, query("SELECT 42")])

        pkts = recv_rfqs(sock, 2)
        assert rows(pkts) == [["42"]]
        assert statuses(pkts) == [?I, ?I]
        refute_more(sock)
      end

      test "answers every bare Sync pipelined while idle", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, [@sync, @sync, @sync])

        assert statuses(recv_rfqs(sock, 3)) == [?I, ?I, ?I]
        refute_more(sock)
      end

      test "mixes simple and extended queries in one write", %{tenant: tenant} do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            query("SELECT 1"),
            extended("SELECT 2"),
            @sync,
            query("SELECT 3"),
            extended("SELECT 4"),
            @sync
          ])

        pkts = recv_rfqs(sock, 4)
        assert rows(pkts) == [["1"], ["2"], ["3"], ["4"]]
        refute_more(sock)
        assert_released(tenant)
      end

      test "runs several Executes under a single Sync", %{tenant: tenant} do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            parse("", "SELECT $1::int"),
            bind("", "", ["1"]),
            execute(""),
            bind("", "", ["2"]),
            execute(""),
            bind("", "", ["3"]),
            execute(""),
            @sync
          ])

        pkts = recv_rfqs(sock, 1)
        assert rows(pkts) == [["1"], ["2"], ["3"]]
        refute_more(sock)
        assert_released(tenant)
      end

      test "answers consecutive Syncs after an extended batch", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, [extended("SELECT 1"), @sync, @sync, @sync])

        pkts = recv_rfqs(sock, 3)
        assert rows(pkts) == [["1"]]
        refute_more(sock)
        assert_released(tenant)
      end

      test "an error in one batch doesn't affect the next pipelined batch", %{tenant: tenant} do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            extended("SELECT 1/0"),
            @sync,
            extended("SELECT 2"),
            @sync
          ])

        pkts = recv_rfqs(sock, 2)
        assert error_codes(pkts) == ["22012"]
        assert rows(pkts) == [["2"]]
        refute_more(sock)
        assert_released(tenant)
      end

      test "holds the backend after an error until the Sync arrives", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, extended("SELECT 1/0"))

        pkts = recv_until(sock, &(error_codes(&1) != []))
        assert error_codes(pkts) == ["22012"]
        assert statuses(pkts) == []
        refute_more(sock)
        assert checked_out(tenant) == 1

        :ok = :gen_tcp.send(sock, @sync)

        assert statuses(recv_rfqs(sock, 1)) == [?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "holds the backend across a Flush until the Sync arrives", %{tenant: tenant} do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            parse("", "SELECT 7"),
            bind("", "", []),
            describe_msg(?P, ""),
            execute(""),
            @flush
          ])

        pkts = recv_until(sock, &Enum.any?(&1, fn pkt -> match?(<<?C, _::binary>>, pkt) end))
        assert rows(pkts) == [["7"]]
        assert statuses(pkts) == []
        refute_more(sock)
        assert checked_out(tenant) == 1

        :ok = :gen_tcp.send(sock, @sync)

        assert statuses(recv_rfqs(sock, 1)) == [?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "handles an extended batch sent one message per write", %{tenant: tenant} do
        sock = connect(tenant)

        for msg <- [parse("", "SELECT $1::int"), bind("", "", ["5"]), execute(""), @sync] do
          :ok = :gen_tcp.send(sock, msg)
          Process.sleep(20)
        end

        pkts = recv_rfqs(sock, 1)
        assert rows(pkts) == [["5"]]
        refute_more(sock)
        assert_released(tenant)
      end

      for chunk_size <- [1, 3, 7, 64] do
        test "handles a pipeline split into #{chunk_size}-byte writes", %{tenant: tenant} do
          sock = connect(tenant)

          bin =
            IO.iodata_to_binary([
              query("SELECT 1"),
              extended("SELECT 2"),
              @sync,
              query("SELECT 3"),
              extended("SELECT 4"),
              @sync
            ])

          for chunk <- chunks(bin, unquote(chunk_size)) do
            :ok = :gen_tcp.send(sock, chunk)
            Process.sleep(1)
          end

          pkts = recv_rfqs(sock, 4)
          assert rows(pkts) == [["1"], ["2"], ["3"], ["4"]]
          refute_more(sock)
          assert_released(tenant)
        end
      end

      test "counts one ReadyForQuery per multi-statement simple query", %{tenant: tenant} do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            query("SELECT 1; SELECT 1/0; SELECT 3"),
            query(""),
            query("SELECT 4")
          ])

        pkts = recv_rfqs(sock, 3)
        assert rows(pkts) == [["1"], ["4"]]
        assert error_codes(pkts) == ["22012"]
        refute_more(sock)
        assert_released(tenant)
      end

      test "releases after a BEGIN..COMMIT pipelined in one write", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, [query("BEGIN"), query("SELECT 1"), query("COMMIT")])

        assert statuses(recv_rfqs(sock, 3)) == [?T, ?T, ?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "keeps the backend for a simple protocol transaction across writes", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, [query("BEGIN"), query("SELECT pg_backend_pid()")])

        pkts = recv_rfqs(sock, 2)
        assert statuses(pkts) == [?T, ?T]
        assert [[backend_pid]] = rows(pkts)
        assert checked_out(tenant) == 1

        Process.sleep(100)
        :ok = :gen_tcp.send(sock, query("SELECT pg_backend_pid()"))

        pkts = recv_rfqs(sock, 1)
        assert rows(pkts) == [[backend_pid]]
        assert statuses(pkts) == [?T]
        assert checked_out(tenant) == 1

        :ok = :gen_tcp.send(sock, query("COMMIT"))

        assert statuses(recv_rfqs(sock, 1)) == [?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "keeps the backend for a failed transaction until ROLLBACK", %{tenant: tenant} do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, [query("BEGIN"), query("SELECT 1/0")])

        pkts = recv_rfqs(sock, 2)
        assert statuses(pkts) == [?T, ?E]
        assert error_codes(pkts) == ["22012"]
        assert checked_out(tenant) == 1

        :ok = :gen_tcp.send(sock, query("SELECT 1"))

        pkts = recv_rfqs(sock, 1)
        assert error_codes(pkts) == ["25P02"]
        assert statuses(pkts) == [?E]
        assert checked_out(tenant) == 1

        :ok = :gen_tcp.send(sock, query("ROLLBACK"))

        assert statuses(recv_rfqs(sock, 1)) == [?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "keeps the backend for an extended protocol transaction across writes", %{
        tenant: tenant
      } do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            extended("BEGIN"),
            @sync,
            extended("SELECT pg_backend_pid()"),
            @sync
          ])

        pkts = recv_rfqs(sock, 2)
        assert statuses(pkts) == [?T, ?T]
        assert [[backend_pid]] = rows(pkts)
        assert checked_out(tenant) == 1

        Process.sleep(100)

        :ok =
          :gen_tcp.send(sock, [
            extended("SELECT pg_backend_pid()"),
            @sync,
            extended("COMMIT"),
            @sync
          ])

        pkts = recv_rfqs(sock, 2)
        assert rows(pkts) == [[backend_pid]]
        assert statuses(pkts) == [?T, ?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "delivers a large result followed by a pipelined query", %{tenant: tenant} do
        sock = connect(tenant)
        n = 50_000

        :ok =
          :gen_tcp.send(sock, [
            query("SELECT generate_series(1, #{n})"),
            query("SELECT 'tail'")
          ])

        pkts = recv_rfqs(sock, 2)
        rows = rows(pkts)
        assert length(rows) == n + 1
        assert List.last(rows) == ["tail"]
        refute_more(sock)
        assert_released(tenant)
      end

      test "handles COPY FROM STDIN via simple query pipelined in one write", %{tenant: tenant} do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            query("BEGIN"),
            query("CREATE TEMP TABLE pipelining_copy (a int) ON COMMIT DROP"),
            query("COPY pipelining_copy FROM STDIN"),
            copy_data("1\n2\n"),
            @copy_done,
            query("SELECT count(*) FROM pipelining_copy"),
            query("COMMIT")
          ])

        pkts = recv_rfqs(sock, 5)
        assert rows(pkts) == [["2"]]
        assert statuses(pkts) == [?T, ?T, ?T, ?T, ?I]
        refute_more(sock)
        assert_released(tenant)
      end

      # libpq sends a Sync right after the Execute of an extended protocol COPY
      # and another one after CopyDone. The backend ignores Syncs during copy-in,
      # so only the second one produces a ReadyForQuery.
      test "handles COPY FROM STDIN via extended protocol with libpq's Syncs", %{tenant: tenant} do
        sock = connect(tenant)

        start_extended_copy(sock, syncs: 1)
        refute_more(sock)

        :ok = :gen_tcp.send(sock, [copy_data("1\n2\n"), @copy_done, @sync])

        assert statuses(recv_rfqs(sock, 1)) == [?T]
        refute_more(sock)

        :ok =
          :gen_tcp.send(sock, [
            query("SELECT count(*) FROM pipelining_copy"),
            query("COMMIT")
          ])

        pkts = recv_rfqs(sock, 2)
        assert rows(pkts) == [["2"]]
        assert statuses(pkts) == [?T, ?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "handles CopyFail via extended protocol with libpq's Syncs", %{tenant: tenant} do
        sock = connect(tenant)

        start_extended_copy(sock, syncs: 1)

        :ok = :gen_tcp.send(sock, [copy_fail("client gave up"), @sync])

        pkts = recv_rfqs(sock, 1)
        assert error_codes(pkts) == ["57014"]
        assert statuses(pkts) == [?E]
        refute_more(sock)

        :ok = :gen_tcp.send(sock, query("ROLLBACK"))

        assert statuses(recv_rfqs(sock, 1)) == [?I]
        refute_more(sock)
        assert_released(tenant)
      end

      # Without waiting for CopyInResponse, a client can't know the COPY never
      # started, so its CopyDone and second Sync reach a backend in normal mode.
      test "answers both Syncs when a blindly pipelined extended COPY fails to start", %{
        tenant: tenant
      } do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            extended("COPY pipelining_missing_table FROM STDIN"),
            @sync,
            copy_data("1\n"),
            @copy_done,
            @sync
          ])

        pkts = recv_rfqs(sock, 2)
        assert error_codes(pkts) == ["42P01"]
        assert statuses(pkts) == [?I, ?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "ignores every Sync sent during an extended COPY", %{tenant: tenant} do
        sock = connect(tenant)

        start_extended_copy(sock, syncs: 5)
        refute_more(sock)

        :ok = :gen_tcp.send(sock, [copy_data("1\n2\n"), @copy_done, @sync])

        assert statuses(recv_rfqs(sock, 1)) == [?T]
        refute_more(sock)

        :ok =
          :gen_tcp.send(sock, [
            query("SELECT count(*) FROM pipelining_copy"),
            query("COMMIT")
          ])

        pkts = recv_rfqs(sock, 2)
        assert rows(pkts) == [["2"]]
        assert statuses(pkts) == [?T, ?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "answers the Sync after CopyDone when an extended COPY fails on bad data", %{
        tenant: tenant
      } do
        sock = connect(tenant)

        start_extended_copy(sock, syncs: 1)

        :ok = :gen_tcp.send(sock, [copy_data("not a number\n"), @copy_done, @sync])

        pkts = recv_rfqs(sock, 1)
        assert error_codes(pkts) == ["22P02"]
        assert statuses(pkts) == [?E]
        refute_more(sock)

        :ok = :gen_tcp.send(sock, query("ROLLBACK"))

        assert statuses(recv_rfqs(sock, 1)) == [?I]
        refute_more(sock)
        assert_released(tenant)
      end

      test "handles COPY TO STDOUT via extended protocol pipelined", %{tenant: tenant} do
        sock = connect(tenant)

        :ok =
          :gen_tcp.send(sock, [
            extended("COPY (SELECT generate_series(1, 3)) TO STDOUT"),
            @sync,
            query("SELECT 'after'")
          ])

        pkts = recv_rfqs(sock, 2)
        assert for(<<?d, _::32, data::binary>> <- pkts, do: data) == ["1\n", "2\n", "3\n"]
        assert rows(pkts) == [["after"]]
        refute_more(sock)
        assert_released(tenant)
      end

      # After an error the backend discards everything up to the Sync, so the
      # Query produces no ReadyForQuery of its own.
      test "releases the backend when a Query is discarded after an extended error", %{
        tenant: tenant
      } do
        sock = connect(tenant)

        :ok = :gen_tcp.send(sock, [extended("SELECT 1/0"), query("SELECT 2"), @sync])

        pkts = recv_rfqs(sock, 1)
        assert error_codes(pkts) == ["22012"]
        assert rows(pkts) == []
        refute_more(sock)
        assert_released(tenant)
      end

      test "closes and re-parses a named statement within one write", %{tenant: tenant} do
        sock = connect(tenant)
        name = "pipelining_stmt_#{System.unique_integer([:positive])}"

        :ok =
          :gen_tcp.send(sock, [
            parse(name, "SELECT $1::int"),
            bind("", name, ["1"]),
            execute(""),
            close(?S, name),
            @sync,
            parse(name, "SELECT $1::int + 1"),
            bind("", name, ["1"]),
            execute(""),
            close(?S, name),
            @sync
          ])

        pkts = recv_rfqs(sock, 2)
        assert error_codes(pkts) == []
        assert rows(pkts) == [["1"], ["2"]]
        refute_more(sock)
        assert_released(tenant)
      end

      # race/3 queues the second write ahead of the db_status that the first
      # write's ReadyForQuery triggers.
      test "delivers a write queued before the previous batch completes", %{tenant: tenant} do
        sock = connect(tenant)

        race(tenant, sock, query("SELECT 'b'"))

        pkts = recv_rfqs(sock, 2)
        assert rows(pkts) == [["a", ""], ["b"]]
        refute_more(sock)
        assert_released(tenant)
      end

      # A Flush gets no reply, so nothing follows the db_status it races.
      test "releases the backend after a write with nothing to answer races the reply", %{
        tenant: tenant
      } do
        sock = connect(tenant)

        race(tenant, sock, @flush)

        pkts = recv_rfqs(sock, 1)
        assert rows(pkts) == [["a", ""]]
        refute_more(sock)
        assert_released(tenant)
      end

      # The next write reaches Supavisor while the previous reply may already be
      # in flight. Replies must never be lost or delivered to another client.
      test "keeps every reply when the next write races the previous reply", %{tenant: tenant} do
        1..4
        |> Enum.map(fn c ->
          Task.async(fn ->
            sock = connect(tenant)

            for i <- 1..150 do
              a = "c#{c}-#{i}-a"
              b = "c#{c}-#{i}-b"

              if rem(i, 2) == 0 do
                :ok = :gen_tcp.send(sock, query("SELECT '#{a}'"))
                spin(rem(i, 50) * 10)
                :ok = :gen_tcp.send(sock, query("SELECT '#{b}'"))

                assert rows(recv_rfqs(sock, 2, 2000)) == [[a], [b]]
              else
                :ok = :gen_tcp.send(sock, [extended("SELECT '#{a}'"), @sync])
                spin(rem(i, 50) * 10)
                :ok = :gen_tcp.send(sock, [extended("SELECT '#{b}'"), @sync])

                assert rows(recv_rfqs(sock, 2, 2000)) == [[a], [b]]
              end
            end

            :gen_tcp.close(sock)
          end)
        end)
        |> Task.await_many(120_000)

        assert_released(tenant)
      end
    end
  end

  @tag named_prepared_statements: true
  test "reuses a named statement across writes and backends", %{tenant: tenant} do
    name = "pipelining_stmt_#{System.unique_integer([:positive])}"

    sock = connect(tenant)
    :ok = :gen_tcp.send(sock, [parse(name, "SELECT $1::int"), @sync])
    assert statuses(recv_rfqs(sock, 1)) == [?I]

    # Other clients hold backends meanwhile, so the statement must follow the
    # client onto backends that never saw its Parse.
    holders =
      for _ <- 1..3 do
        holder = connect(tenant)
        :ok = :gen_tcp.send(holder, query("BEGIN"))
        assert statuses(recv_rfqs(holder, 1)) == [?T]
        holder
      end

    for i <- 1..20 do
      :ok =
        :gen_tcp.send(sock, [
          bind("", name, ["#{i}"]),
          execute(""),
          @sync,
          bind("", name, ["#{i + 1}"]),
          execute(""),
          @sync
        ])

      pkts = recv_rfqs(sock, 2)
      assert error_codes(pkts) == []
      assert rows(pkts) == [["#{i}"], ["#{i + 1}"]]

      if i == 10, do: Enum.each(holders, &:gen_tcp.close/1)
    end

    refute_more(sock)
    assert_released(tenant)
  end

  # With one client at a time the pool reuses a single backend, so this client
  # lands where the statement is already prepared and its Parse isn't sent.
  # Supavisor answers it with its own ParseComplete.
  @tag named_prepared_statements: true
  test "answers a Parse the backend already has in its place in the pipeline", %{
    tenant: tenant
  } do
    prepare_on_backend(tenant, "stmt", "SELECT 1")
    sock = connect(tenant)

    :ok =
      :gen_tcp.send(sock, [
        query("SELECT pg_sleep(0.1)"),
        parse("stmt", "SELECT 1"),
        bind("", "stmt", []),
        execute(""),
        @sync
      ])

    pkts = recv_rfqs(sock, 2)
    assert tags(pkts) == [?T, ?D, ?C, ?Z, ?1, ?2, ?D, ?C, ?Z]
    refute_more(sock)
    assert_released(tenant)
  end

  @tag named_prepared_statements: true
  test "answers a Parse the backend already has when only a Flush follows", %{tenant: tenant} do
    prepare_on_backend(tenant, "stmt", "SELECT 1")
    sock = connect(tenant)

    :ok = :gen_tcp.send(sock, [parse("stmt", "SELECT 1"), @flush])

    assert tags(recv_until(sock, &(&1 != []))) == [?1]
    refute_more(sock)

    :ok = :gen_tcp.send(sock, @sync)

    assert statuses(recv_rfqs(sock, 1)) == [?I]
    refute_more(sock)
    assert_released(tenant)
  end

  # The first client's Parse is skipped after the error, so the backend never creates the
  # statement. The second client lands on the same backend with the same statement, and
  # its Parse must still be sent.
  @tag named_prepared_statements: true
  test "sends a Parse again after the backend skipped it", %{tenant: tenant} do
    sock = connect(tenant)

    :ok =
      :gen_tcp.send(sock, [
        extended("SELECT 1/0"),
        parse("stmt", "SELECT 42"),
        bind("", "stmt", []),
        execute(""),
        @sync
      ])

    pkts = recv_rfqs(sock, 1)
    assert error_codes(pkts) == ["22012"]
    :ok = :gen_tcp.close(sock)
    assert_released(tenant)

    sock = connect(tenant)

    :ok =
      :gen_tcp.send(sock, [parse("stmt", "SELECT 42"), bind("", "stmt", []), execute(""), @sync])

    pkts = recv_rfqs(sock, 1)
    assert error_codes(pkts) == []
    assert rows(pkts) == [["42"]]
    refute_more(sock)
    assert_released(tenant)
  end

  # On a backend without the statement, the Parse sent ahead of the first Bind is skipped
  # after the error. The second Bind comes after the Sync, in the same write, so it's sent
  # before the backend's answer shows the statement was never created.
  @tag named_prepared_statements: true
  @tag skip: "known issue: the second Bind fails once with 26000"
  test "prepares a statement again after the Sync that follows its skipped Parse", %{
    tenant: tenant
  } do
    name = "pipelining_stmt_#{System.unique_integer([:positive])}"
    sock = connect(tenant)

    :ok = :gen_tcp.send(sock, [parse(name, "SELECT 42"), @sync, query("SELECT pg_backend_pid()")])
    assert [[backend_pid]] = rows(recv_rfqs(sock, 2))

    # The pool hands out the most recently returned backend, so the holder takes the one
    # with the statement.
    holder = connect(tenant)
    :ok = :gen_tcp.send(holder, [query("BEGIN"), query("SELECT pg_backend_pid()")])
    assert rows(recv_rfqs(holder, 2)) == [[backend_pid]]

    :ok =
      :gen_tcp.send(sock, [
        execute("missing_portal"),
        bind("", name, []),
        execute(""),
        @sync,
        bind("", name, []),
        execute(""),
        @sync
      ])

    pkts = recv_rfqs(sock, 2)
    assert error_codes(pkts) == ["34000"]
    assert rows(pkts) == [["42"]]
    assert statuses(pkts) == [?I, ?I]
    refute_more(sock)

    :ok = :gen_tcp.close(holder)
    assert_released(tenant)
  end

  # Postgres answers a COPY that fails on bad data right away, and ignores the CopyData the
  # client keeps sending. The backend is idle then, but a CopyData only partly forwarded to
  # it must be finished there.
  test "finishes a partly forwarded CopyData on its backend after the COPY fails", %{
    tenant: tenant
  } do
    sock = connect(tenant)
    <<first::binary-size(8), rest::binary>> = copy_data("2\n3\n4\n")

    :ok =
      :gen_tcp.send(sock, [
        query("CREATE TEMP TABLE pipelining_copy (a int)"),
        query("COPY pipelining_copy FROM STDIN"),
        copy_data("oops\n"),
        first
      ])

    pkts = recv_rfqs(sock, 2)
    assert error_codes(pkts) == ["22P02"]
    assert statuses(pkts) == [?I, ?I]

    # The pool hands out the most recently returned backend, so the holder gets the one
    # that received the first part of the CopyData.
    holder = connect(tenant)
    :ok = :gen_tcp.send(holder, query("BEGIN"))
    assert statuses(recv_rfqs(holder, 1)) == [?T]

    :ok = :gen_tcp.send(sock, [rest, @copy_done, query("SELECT 1")])

    pkts = recv_rfqs(sock, 1)
    assert error_codes(pkts) == []
    assert rows(pkts) == [["1"]]
    refute_more(sock)

    :ok = :gen_tcp.close(holder)
    assert_released(tenant)
  end

  defp connect(tenant) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    port = Application.get_env(:supavisor, :proxy_port_transaction)

    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    ProtocolClient.authenticate(sock, "#{db_conf[:username]}.#{tenant}", db_conf[:password])
    sock
  end

  # Sends a slow query and, while its reply is pending, `write` to a suspended
  # ClientHandler, so `write` is only handled after the reply arrives.
  defp race(tenant, sock, write) do
    client = client_handler(tenant, sock)

    :ok = :gen_tcp.send(sock, query("SELECT 'a', pg_sleep(0.2)"))
    assert_eventually(20, 10, fn -> elem(:sys.get_state(client), 0) == :busy end)

    :ok = :sys.suspend(client)
    :ok = :gen_tcp.send(sock, write)
    Process.sleep(400)
    :ok = :sys.resume(client)
  end

  # Starts an extended protocol COPY into a temp table inside a transaction,
  # followed by `syncs` Syncs, and waits for its CopyInResponse.
  defp start_extended_copy(sock, syncs: syncs) do
    :ok =
      :gen_tcp.send(sock, [
        query("BEGIN"),
        query("CREATE TEMP TABLE pipelining_copy (a int) ON COMMIT DROP"),
        extended("COPY pipelining_copy FROM STDIN"),
        List.duplicate(@sync, syncs)
      ])

    pkts = recv_until(sock, &(length(statuses(&1)) == 2 and copy_in?(&1)))
    assert statuses(pkts) == [?T, ?T]
  end

  defp prepare_on_backend(tenant, name, sql) do
    sock = connect(tenant)
    :ok = :gen_tcp.send(sock, [parse(name, sql), @sync])
    assert tags(recv_rfqs(sock, 1)) == [?1, ?Z]
    :ok = :gen_tcp.close(sock)
    assert_released(tenant)
  end

  defp chunks(bin, size) when byte_size(bin) <= size, do: [bin]

  defp chunks(bin, size) do
    <<chunk::binary-size(size), rest::binary>> = bin
    [chunk | chunks(rest, size)]
  end

  defp spin(us), do: spin_until(System.monotonic_time(:microsecond) + us)

  defp spin_until(deadline) do
    if System.monotonic_time(:microsecond) < deadline, do: spin_until(deadline), else: :ok
  end

  ## Frontend messages

  defp msg(tag, payload), do: <<tag, byte_size(payload) + 4::32, payload::binary>>

  defp query(sql), do: msg(?Q, <<sql::binary, 0>>)

  defp parse(name, sql), do: msg(?P, <<name::binary, 0, sql::binary, 0, 0::16>>)

  # Text-format parameters and results.
  defp bind(portal, stmt, params) do
    encoded = for p <- params, into: <<>>, do: <<byte_size(p)::32, p::binary>>

    msg(
      ?B,
      <<portal::binary, 0, stmt::binary, 0, 0::16, length(params)::16, encoded::binary, 0::16>>
    )
  end

  defp describe_msg(kind, name), do: msg(?D, <<kind, name::binary, 0>>)

  defp execute(portal), do: msg(?E, <<portal::binary, 0, 0::32>>)

  defp close(kind, name), do: msg(?C, <<kind, name::binary, 0>>)

  defp copy_data(data), do: msg(?d, data)

  defp copy_fail(reason), do: msg(?f, <<reason::binary, 0>>)

  # Parse+Bind+Execute on the unnamed statement and portal, without a Sync.
  defp extended(sql), do: [parse("", sql), bind("", "", []), execute("")]

  # N simple queries as one iolist, so a single send pipelines them.
  defp pipeline(n) do
    Enum.map(1..n, fn i -> :pgo_protocol.encode_query_message("SELECT #{i}") end)
  end

  # Zero-parameter Bind (unnamed portal, unnamed statement)
  # -- the minimum needed to Execute an unnamed Parse.
  # https://www.postgresql.org/docs/current/protocol-message-formats.html
  defp encode_bind_message_no_params do
    payload = <<0, 0, 0::16, 0::16, 0::16>>
    <<?B, byte_size(payload) + 4::32, payload::binary>>
  end

  # One Extended Query Protocol batch: Parse+Bind+Execute, with the Sync
  # included or withheld per `sync?`.
  defp extended_batch(sql, sync?: sync?) do
    msgs = [
      :pgo_protocol.encode_parse_message("", sql, []),
      encode_bind_message_no_params(),
      :pgo_protocol.encode_execute_message("", 0)
    ]

    if sync?, do: msgs ++ [:pgo_protocol.encode_sync_message()], else: msgs
  end

  ## Backend messages

  defp recv_rfqs(sock, n, timeout \\ 5000),
    do: recv_until(sock, &(length(statuses(&1)) >= n), timeout)

  # Reads until `done?` holds for the packets received so far, returning them.
  defp recv_until(sock, done?, timeout \\ 5000), do: recv_until(sock, done?, timeout, [], <<>>)

  defp recv_until(sock, done?, timeout, acc, rest) do
    pkts = Enum.reverse(acc)

    if done?.(pkts) do
      pkts
    else
      case :gen_tcp.recv(sock, 0, timeout) do
        {:ok, more} ->
          {new, rest} = Supavisor.Protocol.split_pkts(rest <> more)
          recv_until(sock, done?, timeout, Enum.reverse(new, acc), rest)

        {:error, reason} ->
          flunk(
            "stopped receiving (#{inspect(reason)}) with #{length(statuses(pkts))} ReadyForQuery, " <>
              "rows #{inspect(rows(pkts))}, errors #{inspect(error_codes(pkts))}"
          )
      end
    end
  end

  # Reads until `n` ReadyForQuery packets have been seen, returning the count.
  defp recv_ready_for_queries(sock, n, buf \\ <<>>) do
    {pkts, _rest} = Supavisor.Protocol.split_pkts(buf)
    count = Enum.count(pkts, &match?(<<?Z, _::binary>>, &1))

    if count >= n do
      count
    else
      case :gen_tcp.recv(sock, 0, 5000) do
        {:ok, more} ->
          recv_ready_for_queries(sock, n, buf <> more)

        {:error, reason} ->
          flunk("received only #{count}/#{n} ReadyForQuery before #{inspect(reason)}")
      end
    end
  end

  defp refute_more(sock) do
    assert {:error, :timeout} = :gen_tcp.recv(sock, 0, 200)
  end

  defp tags(pkts), do: for(<<tag, _::binary>> <- pkts, do: tag)

  defp statuses(pkts), do: for(<<?Z, 5::32, status>> <- pkts, do: status)

  defp rows(pkts), do: for(<<?D, _::32, _::16, cols::binary>> <- pkts, do: decode_cols(cols))

  defp decode_cols(<<>>), do: []

  defp decode_cols(<<-1::signed-32, rest::binary>>), do: [nil | decode_cols(rest)]

  defp decode_cols(<<len::32, val::binary-size(len), rest::binary>>),
    do: [val | decode_cols(rest)]

  defp error_codes(pkts), do: for(<<?E, _::32, fields::binary>> <- pkts, do: sqlstate(fields))

  defp sqlstate(<<?C, rest::binary>>), do: rest |> :binary.split(<<0>>) |> hd()

  defp sqlstate(<<_type, rest::binary>>) do
    [_value, rest] = :binary.split(rest, <<0>>)
    sqlstate(rest)
  end

  defp copy_in?(pkts), do: Enum.any?(pkts, &match?(<<?G, _::binary>>, &1))

  ## Pool and backends

  defp checked_out(tenant) do
    {_state, _available, _overflow, checked_out} = :poolboy.status(pool(tenant))
    checked_out
  end

  defp assert_released(tenant) do
    assert_eventually(30, 100, fn -> checked_out(tenant) == 0 end)
  end

  defp pool(tenant), do: elem(pool_entry(tenant), 1)

  defp pool_entry(tenant) do
    entries =
      Registry.select(Supavisor.Registry.Tenants, [{{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}])

    [entry] =
      for {{:pool, _, _, id}, pid} <- entries,
          Supavisor.id(id, :tenant) == tenant,
          do: {id, pid}

    entry
  end

  # The ClientHandler serving `sock`, matched by the client's address.
  defp client_handler(tenant, sock) do
    {:ok, local} = :inet.sockname(sock)
    {id, _pool} = pool_entry(tenant)
    manager = Supavisor.get_local_manager(id)

    Enum.find_value(:ets.tab2list(:sys.get_state(manager).tid), fn {_, pid, _} ->
      {_state, %{sock: {_, port}}} = :sys.get_state(pid)
      :inet.peername(port) == {:ok, local} && pid
    end)
  end

  defp stranded?(observer, marker) do
    {:ok, res} =
      Postgrex.query(
        observer,
        "select 1 from pg_stat_activity where query like $1 and state = 'active' and wait_event_type = 'Client' and wait_event = 'ClientRead'",
        ["%#{marker}%"]
      )

    res.num_rows > 0
  end
end
