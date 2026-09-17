defmodule Supavisor.Protocol.FrontendMessageHandlerTest do
  use ExUnit.Case, async: true

  import Supavisor.Asserts

  alias Supavisor.Protocol.FrontendMessageHandler
  alias Supavisor.Protocol.MessageStreamer

  require MessageStreamer

  setup do
    stream_state = MessageStreamer.new_stream_state(FrontendMessageHandler)

    {:ok, stream_state: stream_state}
  end

  describe "MessageStreamer integration" do
    test "unnamed prepared statements are passed through unchanged", %{
      stream_state: stream_state
    } do
      original_bin = <<?P, 16::32, 0, "select 1", 0, 0, 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state).prepared_statements ==
               MessageStreamer.stream_state(stream_state, :handler_state).prepared_statements

      assert result == [original_bin]
    end

    test "passthrough for message types we ignore", %{
      stream_state: stream_state
    } do
      # Execute message (should pass through)
      original_bin = <<?E, 9::32, 0, 0, 0, 0, 200>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [original_bin]
    end

    test "simple query with prepared statement commands returns error" do
      stream_state = MessageStreamer.new_stream_state(FrontendMessageHandler)

      prepare_bin = <<?Q, 27::32, "PREPARE stmt AS SELECT 1">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, prepare_bin)

      assert_valid_error(error)

      execute_bin = <<?Q, 19::32, "EXECUTE stmt(1)">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, execute_bin)

      assert_valid_error(error)

      deallocate_bin = <<?Q, 19::32, "DEALLOCATE stmt">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, deallocate_bin)

      assert_valid_error(error)
    end

    test "regular simple query passes through unchanged", %{stream_state: stream_state} do
      original_bin = <<?Q, 12::32, "SELECT 1">>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state).prepared_statements ==
               MessageStreamer.stream_state(stream_state, :handler_state).prepared_statements

      assert result == [original_bin]
    end

    test "multiple statements with prepared statement commands returns error" do
      stream_state = MessageStreamer.new_stream_state(FrontendMessageHandler)

      multi_query_bin = <<?Q, 36::32, "SELECT 1; PREPARE stmt AS SELECT 2">>

      assert {:error, %Supavisor.Errors.SimpleQueryNotSupportedError{}} =
               error = MessageStreamer.handle_packets(stream_state, multi_query_bin)

      assert_valid_error(error)
    end

    test "multiple allowed statements pass through unchanged", %{stream_state: stream_state} do
      multi_query_bin = <<?Q, 32::32, "SELECT 1; SELECT 2; SELECT 3">>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, multi_query_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state).prepared_statements ==
               MessageStreamer.stream_state(stream_state, :handler_state).prepared_statements

      assert result == [multi_query_bin]
    end
  end

  # Frames `bin` and returns how many RFQ-producing messages the handler counted.
  defp rfq_producers(stream_state, bin) do
    {:ok, new_stream_state, _result} = MessageStreamer.handle_packets(stream_state, bin)
    MessageStreamer.stream_state(new_stream_state, :handler_state).rfq_producers
  end

  describe "ReadyForQuery-producer counting" do
    test "counts a simple query (Q)", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?Q, 12::32, "SELECT 1">>) == 1
    end

    test "counts a Sync (S)", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?S, 4::32>>) == 1
    end

    test "counts a FunctionCall (F)", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?F, 4::32>>) == 1
    end

    test "does not count Parse or Execute", %{stream_state: stream_state} do
      bin = <<?P, 16::32, 0, "select 1", 0, 0, 0>> <> <<?E, 9::32, 0, 0, 0, 0, 200>>
      assert rfq_producers(stream_state, bin) == 0
    end

    test "counts a multi-statement simple query as one producer", %{stream_state: stream_state} do
      assert rfq_producers(stream_state, <<?Q, 32::32, "SELECT 1; SELECT 2; SELECT 3">>) == 1
    end

    test "counts every query in a pipelined simple-query batch", %{stream_state: stream_state} do
      batch =
        <<?Q, 12::32, "SELECT 1">> <> <<?Q, 12::32, "SELECT 2">> <> <<?Q, 12::32, "SELECT 3">>

      assert rfq_producers(stream_state, batch) == 3
    end

    test "counts only the Sync in an extended-protocol batch", %{stream_state: stream_state} do
      bin =
        <<?P, 16::32, 0, "select 1", 0, 0, 0>> <>
          <<?E, 9::32, 0, 0, 0, 0, 200>> <>
          <<?S, 4::32>>

      assert rfq_producers(stream_state, bin) == 1
    end

    test "counts every Sync in a pipelined extended-protocol batch", %{stream_state: stream_state} do
      sequence =
        <<?P, 16::32, 0, "select 1", 0, 0, 0>> <>
          <<?E, 9::32, 0, 0, 0, 0, 200>> <>
          <<?S, 4::32>>

      assert rfq_producers(stream_state, sequence <> sequence) == 2
    end

    test "still counts (and forwards verbatim) when translation is disabled", %{
      stream_state: stream_state
    } do
      stream_state = MessageStreamer.update_state(stream_state, &%{&1 | translate?: false})
      sync = <<?S, 4::32>>

      {:ok, new_stream_state, result} = MessageStreamer.handle_packets(stream_state, sync)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state).rfq_producers == 1
      assert IO.iodata_to_binary(result) == sync
    end
  end
end
