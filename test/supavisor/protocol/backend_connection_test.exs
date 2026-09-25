defmodule Supavisor.Protocol.BackendConnectionTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.BackendConnection
  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.BackendStorage.LRU

  require BackendConnection

  describe "framing" do
    test "passes through messages that don't move the backend along" do
      bin = <<?R, 8::32, 0::32>> <> <<?N, 5::32, 0>>

      assert {_backend, out, false} = BackendConnection.recv(new(), bin)
      assert IO.iodata_to_binary(out) == bin
    end

    test "waits for the rest of a message it tracks" do
      <<first::binary-size(3), second::binary>> = z(?I)
      backend = BackendConnection.client_write(new(), [?Q])

      assert {backend, [], false} = BackendConnection.recv(backend, first)
      assert {_backend, out, true} = BackendConnection.recv(backend, second)
      assert IO.iodata_to_binary(out) == z(?I)
    end

    test "streams a message it doesn't track without waiting for the rest" do
      row = data_row(String.duplicate("x", 100))
      <<first::binary-size(40), second::binary>> = row
      backend = BackendConnection.client_write(new(), [?Q])

      assert {backend, [^first], false} = BackendConnection.recv(backend, first)

      assert {_backend, out, true} =
               BackendConnection.recv(backend, second <> command_complete("SELECT 1") <> z(?I))

      assert IO.iodata_to_binary(out) == second <> command_complete("SELECT 1") <> z(?I)
    end

    test "forwards the same bytes however the reads are split" do
      backend =
        new()
        |> BackendConnection.query(simple_query("DISCARD ALL"))
        |> BackendConnection.client_write([?P, ?B, ?D, ?E, ?S])

      internal = command_complete("DISCARD ALL") <> z(?I)

      forwarded =
        parse_complete() <>
          bind_complete() <>
          row_description() <>
          data_row("a") <>
          data_row(String.duplicate("b", 20)) <>
          data_row("c") <> command_complete("SELECT 3") <> z(?I)

      responses = internal <> forwarded

      assert {_backend, [^forwarded], true} = BackendConnection.recv(backend, responses)

      for at <- 0..byte_size(responses) do
        <<first::binary-size(at), second::binary>> = responses
        {backend, first_out, _} = BackendConnection.recv(backend, first)
        {backend, second_out, _} = BackendConnection.recv(backend, second)

        assert IO.iodata_to_binary([first_out, second_out]) == forwarded, "split at #{at}"
        assert BackendConnection.synced?(backend), "split at #{at}"
      end
    end

    test "records a FATAL error" do
      backend = BackendConnection.client_write(new(), [?Q])
      fatal = msg(?E, <<"SFATAL", 0, "C57P01", 0, "Mbye", 0, 0>>)

      assert {backend, _out, false} = BackendConnection.recv(backend, fatal)
      assert %{"S" => "FATAL", "C" => "57P01"} = BackendConnection.fatal_error(backend)
    end

    test "doesn't record a plain error as fatal" do
      backend = BackendConnection.client_write(new(), [?Q])

      assert {backend, _out, false} = BackendConnection.recv(backend, error("22012"))
      assert BackendConnection.fatal_error(backend) == nil
    end
  end

  # Each step either records a plain client write (`client_write`) or feeds a backend message
  # (`recv`) along with whether it should leave the backend synced.
  describe "following the backend through forwarded messages" do
    test "a simple query syncs on its ReadyForQuery" do
      run([
        client_write([?Q]),
        recv(row_description(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "pipelined simple queries sync on the last ReadyForQuery" do
      run([client_write([?Q, ?Q]), recv(z(?I), false), recv(z(?I), true)])
    end

    test "a transaction block doesn't sync" do
      backend =
        run([client_write([?Q]), recv(command_complete("BEGIN"), false), recv(z(?T), false)])

      assert BackendConnection.backend(backend, :state) == :in_transaction
    end

    test "an extended batch syncs on its Sync" do
      run([
        client_write([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended batch without its Sync doesn't sync until the Sync" do
      run([
        client_write([?P, ?B, ?E]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        client_write([?S]),
        recv(z(?I), true)
      ])
    end

    test "a Describe completes with RowDescription or NoData" do
      run([
        client_write([?P, ?D, ?B, ?D, ?E, ?S]),
        recv(parse_complete(), false),
        recv(parameter_description(), false),
        recv(row_description(), false),
        recv(bind_complete(), false),
        recv(no_data(), false),
        recv(command_complete("CREATE TABLE"), false),
        recv(z(?I), true)
      ])
    end

    test "Execute completes with EmptyQueryResponse or PortalSuspended" do
      run([
        client_write([?B, ?E, ?B, ?E, ?S]),
        recv(bind_complete(), false),
        recv(empty_query(), false),
        recv(bind_complete(), false),
        recv(portal_suspended(), false),
        recv(z(?I), true)
      ])
    end

    test "a Close completes with CloseComplete and a FunctionCall with ReadyForQuery" do
      run([
        client_write([?C, ?S, ?F]),
        recv(close_complete(), false),
        recv(z(?I), false),
        recv(z(?I), true)
      ])
    end

    test "an error in an extended message ignores the Query before the Sync" do
      run([
        client_write([?P, ?B, ?E, ?Q, ?S]),
        recv(parse_complete(), false),
        recv(error("22012"), false),
        recv(z(?I), true)
      ])
    end

    test "an error in a Query after a completed Execute doesn't ignore the Sync" do
      run([
        client_write([?P, ?B, ?E, ?Q, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(error("22012"), false),
        recv(z(?I), false),
        recv(z(?I), true)
      ])
    end

    test "messages sent after the error are ignored too" do
      run([
        client_write([?P, ?B, ?E]),
        recv(parse_complete(), false),
        recv(error("22012"), false),
        client_write([?Q, ?F, ?S]),
        recv(z(?I), true)
      ])
    end

    test "an error in a simple query doesn't ignore the next one" do
      run([
        client_write([?Q, ?Q]),
        recv(error("22012"), false),
        recv(z(?I), false),
        recv(z(?I), true)
      ])
    end

    test "an error on Sync is followed by its ReadyForQuery" do
      run([
        client_write([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("INSERT 0 1"), false),
        recv(error("23505"), false),
        recv(z(?I), true)
      ])
    end

    test "a simple Query closes an extended batch left without a Sync" do
      run([
        client_write([?P, ?B, ?E, ?Q]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY ignores every Sync sent during copy-in" do
      run([
        client_write([?P, ?B, ?E, ?S, ?S, ?S, ?S, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(copy_in(), false),
        client_write([?c, ?S]),
        recv(command_complete("COPY 2"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY that fails to start answers every Sync" do
      run([
        client_write([?P, ?B, ?E, ?S, ?c, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(error("42P01"), false),
        recv(z(?I), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY ended by CopyFail answers the Sync after it" do
      run([
        client_write([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(copy_in(), false),
        client_write([?f, ?S]),
        recv(error("57014"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY failing on bad data answers the Sync after CopyDone" do
      run([
        client_write([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(copy_in(), false),
        recv(error("22P02"), false),
        client_write([?c, ?S]),
        recv(z(?I), true)
      ])
    end

    test "a simple COPY ignores a Sync sent during copy-in" do
      run([
        client_write([?Q, ?S]),
        recv(copy_in(), false),
        client_write([?c]),
        recv(command_complete("COPY 2"), false),
        recv(z(?I), true)
      ])
    end

    test "a simple COPY failing on bad data syncs on the CopyDone or CopyFail sent after it" do
      for copy_end <- [?c, ?f] do
        run([
          client_write([?Q]),
          recv(copy_in(), false),
          recv(error("22P02"), false),
          recv(z(?I), false),
          client_write([copy_end], true)
        ])
      end
    end

    test "a simple COPY failing on bad data answers messages sent after its CopyDone" do
      run([
        client_write([?Q]),
        recv(copy_in(), false),
        recv(error("22P02"), false),
        recv(z(?I), false),
        client_write([?c, ?Q], false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "a simple COPY failing on bad data syncs on the Query's ReadyForQuery after CopyDone" do
      run([
        client_write([?Q]),
        recv(copy_in(), false),
        client_write([?c]),
        recv(error("22P02"), false),
        recv(z(?I), true)
      ])
    end

    test "a multi-statement Query with a COPY syncs after all statements" do
      run([
        client_write([?Q]),
        recv(command_complete("SELECT 1"), false),
        recv(copy_in(), false),
        client_write([?c]),
        recv(command_complete("COPY 2"), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "CopyDone and CopyFail outside a COPY are ignored" do
      run([client_write([?c, ?f, ?S]), recv(z(?I), true)])
    end

    test "a ReadyForQuery with nothing expected syncs" do
      run([recv(z(?I), true)])
    end

    test "a ReadyForQuery is reported only once" do
      run([client_write([?Q]), recv(z(?I), true), recv(<<?N, 5::32, 0>>, false)])
    end
  end

  describe "prepared statement writes" do
    test "a write is parked until its packets are decided" do
      backend = BackendConnection.client_write(new(), [{:ps, ?B}, ?E, ?S])

      assert queue(backend) == []
      assert BackendConnection.backend(backend, :state) == :idle
    end

    test "responses to earlier writes are followed while a write is parked" do
      backend =
        new()
        |> BackendConnection.client_write([?Q])
        |> BackendConnection.client_write([{:ps, ?B}, ?E, ?S])

      assert {backend, out, false} = BackendConnection.recv(backend, z(?I))
      assert IO.iodata_to_binary(out) == z(?I)

      {backend, to_backend, [], 0} =
        BackendConnection.send_parked_write(backend, [bind("s1"), "execute", "sync"])

      assert IO.iodata_to_binary(to_backend) == "parse(s1)bind(s1)executesync"

      assert {_backend, _out, true} =
               BackendConnection.recv(
                 backend,
                 parse_complete() <> bind_complete() <> command_complete("SELECT 1") <> z(?I)
               )
    end

    test "a Bind or Describe for a statement the backend doesn't have sends its Parse first" do
      for {tag, pkt, message} <- [{?B, bind("s1"), "bind"}, {?D, describe("s1"), "describe"}] do
        {backend, to_backend, [], 0} = send_parked_write(new(), [{:ps, tag}, ?S], [pkt, "s"])

        assert IO.iodata_to_binary(to_backend) == "parse(s1)#{message}(s1)s"

        assert queue(backend) == [
                 {?P, :skip, "s1"},
                 {tag, :forward, "s1"},
                 forward(?S)
               ]

        assert LRU.member?(statements(backend), "s1")
      end
    end

    test "a Bind for a statement the backend has is sent alone" do
      {backend, to_backend, [], 0} =
        send_parked_write(new(["s1"]), [{:ps, ?B}, ?S], [bind("s1"), "s"])

      assert IO.iodata_to_binary(to_backend) == "bind(s1)s"
      assert queue(backend) == [{?B, :forward, "s1"}, forward(?S)]
    end

    test "a statement sent earlier in the same write isn't sent again" do
      pkts = [bind("s1"), "e", bind("s1"), "e", "s"]

      {backend, to_backend, [], 0} =
        send_parked_write(new(), [{:ps, ?B}, ?E, {:ps, ?B}, ?E, ?S], pkts)

      assert IO.iodata_to_binary(to_backend) == "parse(s1)bind(s1)ebind(s1)es"

      assert queue(backend) == [
               {?P, :skip, "s1"},
               {?B, :forward, "s1"},
               forward(?E),
               {?B, :forward, "s1"},
               forward(?E),
               forward(?S)
             ]
    end

    test "a Parse or Close left unsent is answered right away when nothing is pending" do
      for {statements, tag, pkt, reply} <- [
            {["s1"], ?P, parse("s1"), parse_complete()},
            {[], ?C, close("s1"), close_complete()}
          ] do
        {backend, to_backend, due, 0} = send_parked_write(new(statements), [{:ps, tag}], [pkt])

        assert IO.iodata_to_binary(to_backend) == ""
        assert IO.iodata_to_binary(due) == reply
        assert queue(backend) == []
      end
    end

    test "a ParseComplete answered after a ReadyForQuery belongs to the next batch" do
      backend = BackendConnection.client_write(new(["s1"]), [?Q])
      {backend, _to_backend, [], 0} = send_parked_write(backend, [{:ps, ?P}], [parse("s1")])

      assert {backend, out, false} = BackendConnection.recv(backend, z(?I))
      assert IO.iodata_to_binary(out) == z(?I) <> parse_complete()
      assert BackendConnection.backend(backend, :state) == :busy
    end

    test "a Parse not sent is ignored after an error, as the backend would" do
      backend = BackendConnection.client_write(new(["s1"]), [?P])

      {backend, _to_backend, [], 0} =
        send_parked_write(backend, [{:ps, ?P}, ?B, ?S], [parse("s1"), "b", "s"])

      assert {backend, out, true} = BackendConnection.recv(backend, error("42601") <> z(?I))
      assert IO.iodata_to_binary(out) == error("42601") <> z(?I)
      assert LRU.member?(statements(backend), "s1")
    end

    test "an earlier client Parse's response isn't taken by a later intercept" do
      {backend, _to_backend, [], 0} = send_parked_write(new(), [?P, {:ps, ?B}], ["p", bind("s1")])

      responses = parse_complete() <> parse_complete() <> bind_complete()
      assert {_backend, out, false} = BackendConnection.recv(backend, responses)
      assert IO.iodata_to_binary(out) == parse_complete() <> bind_complete()
    end

    test "a Close forgets the statement" do
      {backend, to_backend, [], 0} =
        send_parked_write(new(["s1"]), [{:ps, ?C}, ?S], [close("s1"), "s"])

      assert IO.iodata_to_binary(to_backend) == "close(s1)s"
      refute LRU.member?(statements(backend), "s1")

      assert {_backend, out, true} = BackendConnection.recv(backend, close_complete() <> z(?I))
      assert IO.iodata_to_binary(out) == close_complete() <> z(?I)
    end

    test "a Close for a statement the backend doesn't have is answered after the responses before it" do
      backend = BackendConnection.client_write(new(), [?Q])

      {backend, _to_backend, [], 0} =
        send_parked_write(backend, [{:ps, ?C}, ?S], [close("s1"), "s"])

      assert {backend, out, false} = BackendConnection.recv(backend, z(?I))
      assert IO.iodata_to_binary(out) == z(?I) <> close_complete()

      assert {_backend, _out, true} = BackendConnection.recv(backend, z(?I))
    end

    test "tags that don't match the packets are a bug" do
      backend = BackendConnection.client_write(new(), [{:ps, ?B}])

      assert_raise FunctionClauseError, fn ->
        BackendConnection.send_parked_write(backend, [parse("s1")])
      end
    end

    test "a write without a parked one is a bug" do
      assert_raise FunctionClauseError, fn ->
        BackendConnection.send_parked_write(new(), [bind("s1")])
      end
    end

    test "a plain write while one is parked is a bug" do
      backend = BackendConnection.client_write(new(), [{:ps, ?B}])

      assert_raise FunctionClauseError, fn -> BackendConnection.client_write(backend, [?S]) end
    end
  end

  describe "evictions" do
    setup do
      limit = PreparedStatements.backend_limit()
      old = for i <- 1..limit, do: "old_#{i}"
      {:ok, old: old, evicted: Enum.take(old, div(limit, 5))}
    end

    test "are sent and consumed ahead of the write", %{old: old, evicted: evicted} do
      {backend, to_backend, [], count} =
        send_parked_write(new(old), [{:ps, ?B}, ?S], [bind("s1"), "s"])

      closes = Enum.map_join(evicted, &PreparedStatements.build_close_pkt/1)
      assert count == length(evicted)
      assert IO.iodata_to_binary(to_backend) == closes <> "parse(s1)bind(s1)s"

      assert queue(backend) ==
               Enum.map(evicted, &{?C, :skip, &1}) ++
                 [{?P, :skip, "s1"}, {?B, :forward, "s1"}, forward(?S)]

      responses =
        String.duplicate(close_complete(), count) <>
          parse_complete() <> bind_complete() <> z(?I)

      assert {backend, out, true} = BackendConnection.recv(backend, responses)
      assert IO.iodata_to_binary(out) == bind_complete() <> z(?I)
      assert queue(backend) == []
    end

    test "a statement the write needs is sent again", %{old: old, evicted: evicted} do
      {_backend, to_backend, [], _count} =
        send_parked_write(new(old), [{:ps, ?B}, ?S], [bind("old_1"), "s"])

      closes = Enum.map_join(evicted, &PreparedStatements.build_close_pkt/1)
      assert IO.iodata_to_binary(to_backend) == closes <> "parse(old_1)bind(old_1)s"
    end

    test "a client Close after them keeps its response", %{old: old} do
      tags = [{:ps, ?C}, {:ps, ?B}]

      {backend, _to_backend, [], count} =
        send_parked_write(new(old), tags, [close("old_150"), bind("s1")])

      responses =
        String.duplicate(close_complete(), count) <>
          close_complete() <> parse_complete() <> bind_complete()

      assert {_backend, out, false} = BackendConnection.recv(backend, responses)
      assert IO.iodata_to_binary(out) == close_complete() <> bind_complete()
    end

    test "go right before the first prepared statement packet", %{old: old, evicted: evicted} do
      {backend, _out, false} =
        new(old) |> BackendConnection.client_write([?Q]) |> BackendConnection.recv(copy_in())

      tags = [?c, ?S, {:ps, ?B}, ?E, ?S]
      pkts = ["copy_done", "sync", bind("s1"), "execute", "sync"]
      {backend, to_backend, [], count} = send_parked_write(backend, tags, pkts)

      closes = Enum.map_join(evicted, &PreparedStatements.build_close_pkt/1)

      assert IO.iodata_to_binary(to_backend) ==
               "copy_donesync" <> closes <> "parse(s1)bind(s1)executesync"

      responses =
        command_complete("COPY 1") <>
          z(?I) <>
          z(?I) <>
          String.duplicate(close_complete(), count) <>
          parse_complete() <> bind_complete() <> command_complete("SELECT 1") <> z(?I)

      assert {_backend, out, true} = BackendConnection.recv(backend, responses)

      assert IO.iodata_to_binary(out) ==
               command_complete("COPY 1") <>
                 z(?I) <> z(?I) <> bind_complete() <> command_complete("SELECT 1") <> z(?I)
    end

    test "don't happen below the limit", %{old: old} do
      {_backend, to_backend, [], 0} =
        send_parked_write(new(tl(old)), [{:ps, ?B}, ?S], [bind("s1"), "s"])

      assert IO.iodata_to_binary(to_backend) == "parse(s1)bind(s1)s"
    end
  end

  describe "statements the backend didn't create or close" do
    test "a failed Parse, sent by Supavisor or the client, is forgotten, its error forwarded" do
      for {tag, pkt} <- [{?B, bind("s1")}, {?P, parse("s1")}] do
        {backend, _to_backend, [], 0} = send_parked_write(new(), [{:ps, tag}, ?S], [pkt, "s"])

        assert {backend, out, true} = BackendConnection.recv(backend, error("42P01") <> z(?I))
        assert IO.iodata_to_binary(out) == error("42P01") <> z(?I)
        refute LRU.member?(statements(backend), "s1")
      end
    end

    test "a Parse ignored after an earlier error is forgotten" do
      tags = [{:ps, ?B}, ?E, {:ps, ?B}, ?E, ?S]
      pkts = [bind("x"), "e", bind("s1"), "e", "s"]
      {backend, to_backend, [], 0} = send_parked_write(new(["x"]), tags, pkts)

      assert IO.iodata_to_binary(to_backend) == "bind(x)eparse(s1)bind(s1)es"

      assert {backend, _out, true} =
               BackendConnection.recv(backend, bind_complete() <> error("23505") <> z(?I))

      refute LRU.member?(statements(backend), "s1")
      assert LRU.member?(statements(backend), "x")
    end

    test "a Parse ignored until a later write's Sync is forgotten" do
      backend = BackendConnection.client_write(new(), [?B, ?E])

      {backend, _to_backend, [], 0} =
        send_parked_write(backend, [{:ps, ?B}, ?E], [bind("s1"), "e"])

      assert {backend, _out, false} = BackendConnection.recv(backend, error("23505"))
      backend = BackendConnection.client_write(backend, [?S])

      assert {backend, _out, true} = BackendConnection.recv(backend, z(?I))
      refute LRU.member?(statements(backend), "s1")
    end

    test "a Close ignored after an error, sent or not, leaves the statements as they were" do
      for had_statement? <- [false, true] do
        before = if had_statement?, do: ["s1"], else: []
        backend = BackendConnection.client_write(new(before), [?B, ?E])

        {backend, _to_backend, [], 0} =
          send_parked_write(backend, [{:ps, ?C}, ?S], [close("s1"), "s"])

        refute LRU.member?(statements(backend), "s1")

        responses = bind_complete() <> error("23505") <> z(?I)
        assert {backend, out, true} = BackendConnection.recv(backend, responses)
        assert IO.iodata_to_binary(out) == responses
        assert LRU.member?(statements(backend), "s1") == had_statement?
      end
    end

    test "a Parse failing because the statement exists records it" do
      backend = BackendConnection.client_write(new(["s1"]), [?B, ?E])
      tags = [{:ps, ?C}, ?S, {:ps, ?B}, ?E, ?S]
      pkts = [close("s1"), "s", bind("s1"), "e", "s"]
      {backend, to_backend, [], 0} = send_parked_write(backend, tags, pkts)

      assert IO.iodata_to_binary(to_backend) == "close(s1)sparse(s1)bind(s1)es"

      responses = bind_complete() <> error("23505") <> z(?I) <> error("42P05") <> z(?I)
      assert {backend, out, true} = BackendConnection.recv(backend, responses)
      assert IO.iodata_to_binary(out) == responses
      assert LRU.member?(statements(backend), "s1")

      {_backend, to_backend, [], 0} =
        send_parked_write(backend, [{:ps, ?B}, ?S], [bind("s1"), "s"])

      assert IO.iodata_to_binary(to_backend) == "bind(s1)s"
    end

    test "a Bind failing because the statement doesn't exist forgets it" do
      backend = BackendConnection.client_write(new(), [?B, ?E])

      {backend, to_backend, [], 0} =
        send_parked_write(backend, [{:ps, ?P}, {:ps, ?C}, ?S], [parse("s1"), close("s1"), "s"])

      assert IO.iodata_to_binary(to_backend) == "parse(s1)close(s1)s"

      assert {backend, _out, true} =
               BackendConnection.recv(backend, bind_complete() <> error("23505") <> z(?I))

      assert LRU.member?(statements(backend), "s1")

      {backend, _to_backend, [], 0} =
        send_parked_write(backend, [{:ps, ?B}, ?S], [bind("s1"), "s"])

      assert {backend, out, true} = BackendConnection.recv(backend, error("26000") <> z(?I))
      assert IO.iodata_to_binary(out) == error("26000") <> z(?I)
      refute LRU.member?(statements(backend), "s1")

      {_backend, to_backend, [], 0} =
        send_parked_write(backend, [{:ps, ?B}, ?S], [bind("s1"), "s"])

      assert IO.iodata_to_binary(to_backend) == "parse(s1)bind(s1)s"
    end
  end

  describe "queries run by Supavisor" do
    test "none of their responses reach the client" do
      backend = BackendConnection.query(new(), extended_query())

      responses =
        parse_complete() <>
          bind_complete() <>
          row_description() <>
          data_row("x") <>
          command_complete("SELECT 1") <> <<?S, 8::32, "a", 0, "b", 0>> <> z(?I)

      assert {backend, [], true} = BackendConnection.recv(backend, responses)
      assert queue(backend) == []
    end

    test "a DataRow split across reads is consumed" do
      backend = BackendConnection.query(new(), extended_query())
      row = data_row(String.duplicate("x", 100))
      <<first::binary-size(40), second::binary>> = row

      assert {backend, [], false} =
               BackendConnection.recv(backend, parse_complete() <> bind_complete() <> first)

      assert BackendConnection.backend(backend, :buffer) == <<>>

      assert {_backend, [], true} =
               BackendConnection.recv(backend, second <> command_complete("SELECT 1") <> z(?I))
    end

    test "an error is consumed too" do
      backend = BackendConnection.query(new(), simple_query("DISCARD ALL"))

      assert {_backend, [], true} = BackendConnection.recv(backend, error("25001") <> z(?I))
    end

    test "responses after them reach the client" do
      backend =
        new()
        |> BackendConnection.query(simple_query("DISCARD ALL"))
        |> BackendConnection.client_write([?Q])

      responses = command_complete("DISCARD ALL") <> z(?I) <> data_row("x") <> z(?I)

      assert {_backend, out, true} = BackendConnection.recv(backend, responses)
      assert IO.iodata_to_binary(out) == data_row("x") <> z(?I)
    end
  end

  defp new(statements \\ []) do
    backend = BackendConnection.new(LRU)

    BackendConnection.backend(backend,
      statements: Enum.reduce(statements, LRU.new(), &LRU.put(&2, &1))
    )
  end

  defp send_parked_write(backend, tags, pkts) do
    backend |> BackendConnection.client_write(tags) |> BackendConnection.send_parked_write(pkts)
  end

  defp queue(backend), do: :queue.to_list(BackendConnection.backend(backend, :requests))
  defp statements(backend), do: BackendConnection.backend(backend, :statements)
  defp forward(message), do: {message, :forward, nil}

  defp parse(name), do: {:parse_pkt, name, "parse(#{name})"}
  defp bind(name), do: {:bind_pkt, name, "bind(#{name})", "parse(#{name})"}
  defp describe(name), do: {:describe_pkt, name, "describe(#{name})", "parse(#{name})"}
  defp close(name), do: {:close_pkt, name, "close(#{name})"}

  defp client_write(tags), do: {:client_write, tags}
  defp client_write(tags, synced?), do: {:client_write, tags, synced?}
  defp recv(bin, synced?), do: {:recv, bin, synced?}

  defp run(steps) do
    Enum.reduce(steps, new(), fn
      {:client_write, tags}, backend ->
        BackendConnection.client_write(backend, tags)

      {:client_write, tags, synced?}, backend ->
        backend = BackendConnection.client_write(backend, tags)

        assert BackendConnection.synced?(backend) == synced?,
               "after #{inspect(tags)}: queue #{inspect(queue(backend))}, state #{inspect(BackendConnection.backend(backend, :state))}"

        backend

      {:recv, bin, synced?}, backend ->
        {backend, _out, actual} = BackendConnection.recv(backend, bin)

        assert actual == synced?,
               "after #{inspect(bin)}: queue #{inspect(queue(backend))}, state #{inspect(BackendConnection.backend(backend, :state))}"

        backend
    end)
  end

  defp extended_query, do: Supavisor.Protocol.Server.extended_query("SELECT 1")
  defp simple_query(sql), do: :pgo_protocol.encode_query_message(sql)

  defp msg(tag, payload), do: <<tag, byte_size(payload) + 4::32, payload::binary>>
  defp z(status), do: <<?Z, 5::32, status>>
  defp parse_complete, do: <<?1, 4::32>>
  defp bind_complete, do: <<?2, 4::32>>
  defp close_complete, do: <<?3, 4::32>>
  defp no_data, do: <<?n, 4::32>>
  defp empty_query, do: <<?I, 4::32>>
  defp portal_suspended, do: <<?s, 4::32>>
  defp row_description, do: msg(?T, <<0::16>>)
  defp parameter_description, do: msg(?t, <<0::16>>)
  defp data_row(value), do: msg(?D, <<1::16, byte_size(value)::32, value::binary>>)
  defp command_complete(tag), do: msg(?C, <<tag::binary, 0>>)
  defp copy_in, do: msg(?G, <<0, 0::16>>)
  defp error(code), do: msg(?E, <<"SERROR", 0, "C", code::binary, 0, "Mboom", 0, 0>>)
end
