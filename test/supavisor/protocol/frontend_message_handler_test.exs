defmodule Supavisor.Protocol.FrontendMessageHandlerTest do
  use ExUnit.Case, async: true

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

      assert {:error, :prepared_statement_on_simple_query} =
               MessageStreamer.handle_packets(stream_state, prepare_bin)

      execute_bin = <<?Q, 19::32, "EXECUTE stmt(1)">>

      assert {:error, :prepared_statement_on_simple_query} =
               MessageStreamer.handle_packets(stream_state, execute_bin)

      deallocate_bin = <<?Q, 19::32, "DEALLOCATE stmt">>

      assert {:error, :prepared_statement_on_simple_query} =
               MessageStreamer.handle_packets(stream_state, deallocate_bin)
    end

    test "regular simple query passes through unchanged", %{stream_state: stream_state} do
      original_bin = <<?Q, 12::32, "SELECT 1">>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [original_bin]
    end

    test "multiple statements with prepared statement commands returns error" do
      stream_state = MessageStreamer.new_stream_state(FrontendMessageHandler)

      multi_query_bin = <<?Q, 36::32, "SELECT 1; PREPARE stmt AS SELECT 2">>

      assert {:error, :prepared_statement_on_simple_query} =
               MessageStreamer.handle_packets(stream_state, multi_query_bin)
    end

    test "multiple allowed statements pass through unchanged", %{stream_state: stream_state} do
      multi_query_bin = <<?Q, 32::32, "SELECT 1; SELECT 2; SELECT 3">>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, multi_query_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [multi_query_bin]
    end
  end
end
