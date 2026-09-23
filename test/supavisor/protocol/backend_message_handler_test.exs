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

    test "ready for query message with no actions passes through unchanged", %{
      stream_state: stream_state
    } do
      original_bin = <<?Z, 5::32, ?I>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # The action queue is untouched.
      assert BackendMessageHandler.handler_state(
               MessageStreamer.stream_state(new_stream_state, :handler_state),
               :action_queue
             ) == :queue.new()

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "parse complete message with intercept action is intercepted", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:intercept, :parse}, queue)
          )
        end)

      original_bin = <<?1, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(result) == <<>>
    end

    test "close complete message with intercept action is intercepted", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:intercept, :close}, queue)
          )
        end)

      original_bin = <<?3, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(result) == <<>>
    end

    test "parameter description message with intercept action is intercepted", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:intercept, :parameter_description}, queue)
          )
        end)

      original_bin = <<?t, 10::32, 1::16, 23::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(result) == <<>>
    end

    test "parse complete message with forward action is forwarded", %{stream_state: stream_state} do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:forward, :parse}, queue)
          )
        end)

      original_bin = <<?1, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "close complete message with forward action is forwarded", %{stream_state: stream_state} do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:forward, :close}, queue)
          )
        end)

      original_bin = <<?3, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "parameter description message with forward action is forwarded", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:forward, :parameter_description}, queue)
          )
        end)

      original_bin = <<?t, 10::32, 1::16, 23::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(result) == original_bin
    end

    test "parameter description message with inject parse action injects parse complete", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:inject, :parse}, queue)
          )
        end)

      original_bin = <<?t, 10::32, 1::16, 23::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(result) == <<?1, 4::32, original_bin::binary>>
    end

    test "multiple actions are processed in order" do
      stream_state = MessageStreamer.new_stream_state(BackendMessageHandler)

      stream_state_with_actions =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          queue = :queue.in({:inject, :parse}, queue)
          queue = :queue.in({:forward, :close}, queue)
          BackendMessageHandler.handler_state(s, action_queue: queue)
        end)

      parameter_desc_bin = <<?t, 10::32, 1::16, 23::32>>
      close_bin = <<?3, 4::32>>

      {:ok, stream_state_after_param, param_result} =
        MessageStreamer.handle_packets(stream_state_with_actions, parameter_desc_bin)

      remaining_state =
        MessageStreamer.stream_state(stream_state_after_param, :handler_state)

      remaining_queue = BackendMessageHandler.handler_state(remaining_state, :action_queue)
      assert :queue.len(remaining_queue) == 1
      assert {:value, {:forward, :close}} = :queue.peek(remaining_queue)

      assert IO.iodata_to_binary(param_result) == <<?1, 4::32, parameter_desc_bin::binary>>

      {:ok, stream_state_after_close, close_result} =
        MessageStreamer.handle_packets(stream_state_after_param, close_bin)

      assert MessageStreamer.stream_state(stream_state_after_close, :handler_state) ==
               BackendMessageHandler.init_state()

      assert IO.iodata_to_binary(close_result) == close_bin
    end

    test "non-matching action type is kept for later" do
      stream_state = MessageStreamer.new_stream_state(BackendMessageHandler)

      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn BackendMessageHandler.handler_state(
                                                        action_queue: queue
                                                      ) = s ->
          BackendMessageHandler.handler_state(s,
            action_queue: :queue.in({:intercept, :close}, queue)
          )
        end)

      original_bin = <<?1, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      remaining_state = MessageStreamer.stream_state(new_stream_state, :handler_state)
      remaining_queue = BackendMessageHandler.handler_state(remaining_state, :action_queue)
      assert :queue.len(remaining_queue) == 1
      assert {:value, {:intercept, :close}} = :queue.peek(remaining_queue)

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
        resolve_ps(2, [?P, ?B]),
        recv(parse_complete(), false),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "a placeholder can resolve to nothing, for a Parse that wasn't sent" do
      run([
        send([:ps, ?B, ?E, ?S]),
        resolve_ps(1, []),
        recv(bind_complete(), false),
        recv(command_complete("SELECT 1"), false),
        recv(z(?I), true)
      ])
    end

    test "a ReadyForQuery with nothing expected syncs" do
      run([recv(z(?I), true)])
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

  defp send(tags), do: {:send, tags}
  defp resolve_ps(count, tags), do: {:resolve_ps, count, tags}
  defp recv(bin, synced?), do: {:recv, bin, synced?}

  defp run(steps) do
    Enum.reduce(steps, MessageStreamer.new_stream_state(BackendMessageHandler), fn
      {:send, tags}, stream_state ->
        MessageStreamer.update_state(stream_state, &BackendMessageHandler.expect(&1, tags))

      {:resolve_ps, count, tags}, stream_state ->
        MessageStreamer.update_state(
          stream_state,
          &BackendMessageHandler.resolve_ps(&1, count, tags)
        )

      {:recv, bin, synced?}, stream_state ->
        {:ok, stream_state, _pkts} = MessageStreamer.handle_packets(stream_state, bin)
        hs = MessageStreamer.stream_state(stream_state, :handler_state)

        assert BackendMessageHandler.synced?(hs) == synced?,
               "after #{inspect(bin)}: pending #{inspect(:queue.to_list(BackendMessageHandler.handler_state(hs, :pending)))}, mode #{inspect(BackendMessageHandler.handler_state(hs, :mode))}"

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
