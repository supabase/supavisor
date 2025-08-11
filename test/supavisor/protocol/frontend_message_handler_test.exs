defmodule Supavisor.Protocol.FrontendMessageHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.MessageStreamer
  alias Supavisor.Protocol.FrontendMessageHandler

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

    test "streaming parsing works correctly regardless of packet sizes" do
      stream_state = MessageStreamer.new_stream_state(FrontendMessageHandler)

      full_binary =
        [
          <<?P, 26::32, "test_stmt1", 0, "select 1", 0, 0, 0>>,
          <<?B, 22::32, 0, "test_stmt1", 0, 0, 0, 0, 0, 0, 0>>,
          <<?E, 9::32, 0, 0, 0, 0, 200>>,
          <<?S, 4::32>>,
          <<?C, 16::32, ?S, "test_stmt1", 0>>,
          <<?P, 26::32, "test_stmt2", 0, "select 2", 0, 0, 0>>,
          <<?B, 22::32, 0, "test_stmt2", 0, 0, 0, 0, 0, 0, 0>>,
          <<?E, 9::32, 0, 0, 0, 0, 201>>,
          <<?P, 26::32, "test_stmt3", 0, "select 3", 0, 0, 0>>,
          <<?D, 16::32, ?S, "test_stmt3", 0>>,
          <<?S, 4::32>>
        ]
        |> IO.iodata_to_binary()

      for chunk_size <- [1, 3, 7, 13, 23, 37] do
        {final_state, result} =
          full_binary
          |> chunk_binary(chunk_size)
          |> Enum.reduce({stream_state, []}, fn chunk, {state, acc} ->
            {:ok, new_state, chunk_result} = MessageStreamer.handle_packets(state, chunk)
            {new_state, acc ++ chunk_result}
          end)

        # Group consecutive binaries together while preserving order. Helps with making assertion easier
        grouped_result =
          Enum.reduce(result, [], fn
            raw_bin, [] when is_binary(raw_bin) ->
              [raw_bin]

            raw_bin, [last | rest] when is_binary(raw_bin) and is_binary(last) ->
              [<<last::binary, raw_bin::binary>> | rest]

            raw_bin, acc when is_binary(raw_bin) ->
              [raw_bin | acc]

            tuple, acc ->
              [tuple | acc]
          end)
          |> Enum.reverse()

        assert [
                 {:parse_pkt, _, _},
                 {:bind_pkt, _, _, _},
                 <<?E, 9::32, 0, 0, 0, 0, 200, ?S, 4::32>>,
                 {:close_pkt, _, _},
                 {:parse_pkt, _, _},
                 {:bind_pkt, _, _, _},
                 <<?E, 9::32, 0, 0, 0, 0, 201>>,
                 {:parse_pkt, _, _},
                 {:describe_pkt, _, _},
                 <<?S, 4::32>>
               ] = grouped_result

        assert MessageStreamer.stream_state(final_state, :pending_bin) == <<>>
        assert MessageStreamer.stream_state(final_state, :in_flight_pkt) == nil
      end
    end

    test "simple query with PREPARE statement returns error" do
      stream_state = MessageStreamer.new_stream_state(FrontendMessageHandler)

      # Simple query with PREPARE
      original_bin = <<?Q, 20::32, "PREPARE stmt AS SELECT 1">>

      assert {:error, :prepared_statement_on_simple_query} =
               MessageStreamer.handle_packets(stream_state, original_bin)
    end

    test "regular simple query passes through unchanged", %{stream_state: stream_state} do
      # Regular simple query
      original_bin = <<?Q, 12::32, "SELECT 1">>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [original_bin]
    end
  end

  defp chunk_binary(binary, chunk_size) when byte_size(binary) <= chunk_size do
    [binary]
  end

  defp chunk_binary(binary, chunk_size) do
    <<chunk::binary-size(chunk_size), rest::binary>> = binary
    [chunk | chunk_binary(rest, chunk_size)]
  end
end
