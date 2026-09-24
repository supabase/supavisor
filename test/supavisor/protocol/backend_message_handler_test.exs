defmodule Supavisor.Protocol.BackendMessageHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.BackendMessageHandler
  alias Supavisor.Protocol.MessageStreamer

  require BackendMessageHandler
  require MessageStreamer

  setup do
    stream_state = MessageStreamer.new_stream_state(BackendMessageHandler)
    {:ok, stream_state: stream_state}
  end

  describe "MessageStreamer integration" do
    test "parse complete message with no actions passes through unchanged", %{
      stream_state: stream_state
    } do
      original_bin = <<?1, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "close complete message with no actions passes through unchanged", %{
      stream_state: stream_state
    } do
      original_bin = <<?3, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "parameter description message with no actions passes through unchanged", %{
      stream_state: stream_state
    } do
      original_bin = <<?t, 10::32, 1::16, 23::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "ready for query message passes through unchanged", %{stream_state: stream_state} do
      original_bin = <<?Z, 5::32, ?I>>

      {:ok, _new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "passthrough for unhandled message types", %{stream_state: stream_state} do
      original_bin = <<?R, 8::32, 0::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert IO.iodata_to_binary(result) == original_bin
    end
  end

  # Each step either queues frontend messages (`send`), resolves prepared statement
  # placeholders (`resolve_ps`) or feeds a backend message (`recv`) along with whether
  # the backend should be considered synced right after it.
  describe "following the backend through forwarded messages" do
    test "a simple query syncs on its ReadyForQuery" do
      run([
        send([?Q]),
        recv(row_description(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "pipelined simple queries sync on the last ReadyForQuery" do
      run([send([?Q, ?Q]), recv(z(?I), false), recv(z(?I), true)])
    end

    test "a transaction block doesn't sync" do
      run([send([?Q]), recv(command_complete("BEGIN"), false), recv(z(?T), false)])
    end

    test "an extended batch syncs on its Sync" do
      run([
        send([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended batch without its Sync doesn't sync until the Sync" do
      run([
        send([?P, ?B, ?E]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        send([?S]),
        recv(z(?I), true)
      ])
    end

    test "a Describe completes with RowDescription, NoData or after ParameterDescription" do
      run([
        send([?P, ?D, ?B, ?D, ?E, ?S]),
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
        send([?B, ?E, ?B, ?E, ?S]),
        recv(bind_complete(), false),
        recv(empty_query(), false),
        recv(bind_complete(), false),
        recv(portal_suspended(), false),
        recv(z(?I), true)
      ])
    end

    test "a Close completes with CloseComplete and a FunctionCall with ReadyForQuery" do
      run([
        send([?C, ?S, ?F]),
        recv(close_complete(), false),
        recv(z(?I), false),
        recv(z(?I), true)
      ])
    end

    test "an error in an extended message skips the Query before the Sync" do
      run([
        send([?P, ?B, ?E, ?Q, ?S]),
        recv(parse_complete(), false),
        recv(error("22012"), false),
        recv(z(?I), true)
      ])
    end

    test "an error in a Query after a completed Execute doesn't skip" do
      run([
        send([?P, ?B, ?E, ?Q, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(error("22012"), false),
        recv(z(?I), false),
        recv(z(?I), true)
      ])
    end

    test "messages sent after the error are skipped too" do
      run([
        send([?P, ?B, ?E]),
        recv(parse_complete(), false),
        recv(error("22012"), false),
        send([?Q, ?F, ?S]),
        recv(z(?I), true)
      ])
    end

    test "an error in a simple query doesn't skip the next one" do
      run([send([?Q, ?Q]), recv(error("22012"), false), recv(z(?I), false), recv(z(?I), true)])
    end

    test "an error on Sync is followed by its ReadyForQuery" do
      run([
        send([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("INSERT 0 1"), false),
        recv(error("23505"), false),
        recv(z(?I), true)
      ])
    end

    test "a simple Query closes an extended batch left without a Sync" do
      run([
        send([?P, ?B, ?E, ?Q]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY ignores the Sync sent before its data" do
      run([
        send([?P, ?B, ?D, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(no_data(), false),
        recv(copy_in(), false),
        send([?c, ?S]),
        recv(command_complete("COPY 2"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY ignores every Sync sent during copy-in" do
      run([
        send([?P, ?B, ?E, ?S, ?S, ?S, ?S, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(copy_in(), false),
        send([?c, ?S]),
        recv(command_complete("COPY 2"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY that fails to start answers every Sync" do
      run([
        send([?P, ?B, ?E, ?S, ?c, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(error("42P01"), false),
        recv(z(?I), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY ended by CopyFail answers the Sync after it" do
      run([
        send([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(copy_in(), false),
        send([?f, ?S]),
        recv(error("57014"), false),
        recv(z(?I), true)
      ])
    end

    test "an extended COPY failing on bad data answers the Sync after CopyDone" do
      run([
        send([?P, ?B, ?E, ?S]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(copy_in(), false),
        recv(error("22P02"), false),
        send([?c, ?S]),
        recv(z(?I), true)
      ])
    end

    test "a simple COPY syncs on the Query's ReadyForQuery" do
      run([
        send([?Q]),
        recv(copy_in(), false),
        send([?c]),
        recv(command_complete("COPY 2"), false),
        recv(z(?I), true)
      ])
    end

    test "a simple COPY ignores a Sync sent during copy-in" do
      run([
        send([?Q, ?S]),
        recv(copy_in(), false),
        send([?c]),
        recv(command_complete("COPY 2"), false),
        recv(z(?I), true)
      ])
    end

    test "a simple COPY failing on bad data syncs on the Query's ReadyForQuery" do
      run([send([?Q]), recv(copy_in(), false), recv(error("22P02"), false), recv(z(?I), true)])
    end

    test "a multi-statement Query with a COPY syncs after all statements" do
      run([
        send([?Q]),
        recv(command_complete("SELECT 1"), false),
        recv(copy_in(), false),
        send([?c]),
        recv(command_complete("COPY 2"), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "CopyDone and CopyFail outside a COPY are ignored" do
      run([send([?c, ?f, ?S]), recv(z(?I), true)])
    end

    test "prepared statement placeholders resolve to what was sent" do
      run([
        send([?Q, :ps, :ps, ?E, ?S]),
        recv(z(?I), false),
        resolve_ps([[?P], [?B]]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "placeholders spread through a write each resolve to what was sent for them" do
      run([
        send([:ps, ?E, :ps, ?E, ?S]),
        resolve_ps([[?B], [{:intercept, ?P}, ?B]]),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "a placeholder can resolve to nothing, for a Parse that wasn't sent" do
      run([
        send([:ps, ?B, ?E, ?S]),
        resolve_ps([[]]),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "a ReadyForQuery with nothing expected syncs" do
      run([recv(z(?I), true)])
    end

    test "take_synced reports a ReadyForQuery only once" do
      {:ok, stream_state, _pkts} =
        MessageStreamer.handle_packets(MessageStreamer.new_stream_state(BackendMessageHandler), z(?I))

      hs = MessageStreamer.stream_state(stream_state, :handler_state)

      assert {true, hs} = BackendMessageHandler.take_synced(hs)
      assert {false, _hs} = BackendMessageHandler.take_synced(hs)
    end

    test "reset_sync forgets what was expected" do
      state =
        BackendMessageHandler.init_state()
        |> BackendMessageHandler.expect([?Q])
        |> BackendMessageHandler.reset_sync()

      refute BackendMessageHandler.synced?(state)
      assert BackendMessageHandler.handler_state(state, :pending) == :queue.new()
    end
  end

  describe "prepared statement messages" do
    test "the response to a Parse sent by Supavisor is intercepted" do
      {_stream_state, out} =
        feed([{:intercept, ?P}, ?B, ?E, ?S], [
          parse_complete(),
          bind_complete(),
          command_complete("SELECT 1"),
          z(?I)
        ])

      assert out == bind_complete() <> command_complete("SELECT 1") <> z(?I)
    end

    test "an earlier client Parse's response isn't taken by a later intercept" do
      {_stream_state, out} =
        feed([?P, {:intercept, ?P}, ?B], [parse_complete(), parse_complete(), bind_complete()])

      assert out == parse_complete() <> bind_complete()
    end

    test "an earlier client Close's response isn't taken by a later eviction" do
      {_stream_state, out} = feed([?C, {:intercept, ?C}], [close_complete(), close_complete()])

      assert out == close_complete()
    end

    test "an error on a Parse sent by Supavisor is forwarded and skips until Sync" do
      {stream_state, out} = feed([{:intercept, ?P}, ?B, ?E, ?S], [error("42P01"), z(?I)])

      assert out == error("42P01") <> z(?I)
      assert synced?(stream_state)
    end

    test "a Parse not sent is answered after the response before it" do
      {_stream_state, out} =
        feed([?Q, :parse_complete, ?B, ?S], [z(?I), bind_complete(), z(?I)])

      assert out == z(?I) <> parse_complete() <> bind_complete() <> z(?I)
    end

    test "a Parse not sent with nothing before it is answered on resolve" do
      state = BackendMessageHandler.expect(BackendMessageHandler.init_state(), [:ps, ?H])

      assert {state, [due]} = BackendMessageHandler.resolve_ps(state, [[:parse_complete]])
      assert due == parse_complete()
      assert :queue.to_list(BackendMessageHandler.handler_state(state, :pending)) == [?H]
    end

    test "a Parse not sent after an error is skipped like the backend would" do
      {stream_state, out} = feed([?P, :parse_complete, ?B, ?S], [error("42601"), z(?I)])

      assert out == error("42601") <> z(?I)
      assert synced?(stream_state)
    end
  end

  defp feed(tags, bins) do
    stream_state =
      MessageStreamer.update_state(
        MessageStreamer.new_stream_state(BackendMessageHandler),
        &BackendMessageHandler.expect(&1, tags)
      )

    Enum.reduce(bins, {stream_state, <<>>}, fn bin, {stream_state, out} ->
      {:ok, stream_state, pkts} = MessageStreamer.handle_packets(stream_state, bin)
      {stream_state, out <> IO.iodata_to_binary(pkts)}
    end)
  end

  defp synced?(stream_state),
    do: BackendMessageHandler.synced?(MessageStreamer.stream_state(stream_state, :handler_state))

  defp send(tags), do: {:send, tags}
  defp resolve_ps(resolved), do: {:resolve_ps, resolved}
  defp recv(bin, synced?), do: {:recv, bin, synced?}

  defp run(steps) do
    Enum.reduce(steps, MessageStreamer.new_stream_state(BackendMessageHandler), fn
      {:send, tags}, stream_state ->
        MessageStreamer.update_state(stream_state, &BackendMessageHandler.expect(&1, tags))

      {:resolve_ps, resolved}, stream_state ->
        MessageStreamer.update_state(stream_state, fn hs ->
          {hs, []} = BackendMessageHandler.resolve_ps(hs, resolved)
          hs
        end)

      {:recv, bin, synced?}, stream_state ->
        {:ok, stream_state, _pkts} = MessageStreamer.handle_packets(stream_state, bin)
        hs = MessageStreamer.stream_state(stream_state, :handler_state)

        assert BackendMessageHandler.synced?(hs) == synced?,
               "after #{inspect(bin)}: pending #{inspect(:queue.to_list(BackendMessageHandler.handler_state(hs, :pending)))}, phase #{inspect(BackendMessageHandler.handler_state(hs, :phase))}"

        stream_state
    end)
  end

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
  defp command_complete(tag), do: msg(?C, <<tag::binary, 0>>)
  defp copy_in, do: msg(?G, <<0, 0::16>>)
  defp error(code), do: msg(?E, <<"SERROR", 0, "C", code::binary, 0, "Mboom", 0, 0>>)
end
