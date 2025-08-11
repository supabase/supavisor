defmodule Supavisor.Protocol.BackendMessageHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.MessageStreamer
  alias Supavisor.Protocol.BackendMessageHandler

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

    test "parse complete message with intercept action is intercepted", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:intercept, :parse}, queue)
        end)

      original_bin = <<?1, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) == :queue.new()
      assert IO.iodata_to_binary(result) == <<>>
    end

    test "close complete message with intercept action is intercepted", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:intercept, :close}, queue)
        end)

      original_bin = <<?3, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) == :queue.new()
      assert IO.iodata_to_binary(result) == <<>>
    end

    test "parameter description message with intercept action is intercepted", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:intercept, :parameter_description}, queue)
        end)

      original_bin = <<?t, 10::32, 1::16, 23::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) == :queue.new()
      assert IO.iodata_to_binary(result) == <<>>
    end

    test "parse complete message with forward action is forwarded", %{stream_state: stream_state} do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:forward, :parse}, queue)
        end)

      original_bin = <<?1, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) == :queue.new()
      assert IO.iodata_to_binary(result) == original_bin
    end

    test "close complete message with forward action is forwarded", %{stream_state: stream_state} do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:forward, :close}, queue)
        end)

      original_bin = <<?3, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) == :queue.new()
      assert IO.iodata_to_binary(result) == original_bin
    end

    test "parameter description message with forward action is forwarded", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:forward, :parameter_description}, queue)
        end)

      original_bin = <<?t, 10::32, 1::16, 23::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) == :queue.new()
      assert IO.iodata_to_binary(result) == original_bin
    end

    test "parameter description message with inject parse action injects parse complete", %{
      stream_state: stream_state
    } do
      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:inject, :parse}, queue)
        end)

      original_bin = <<?t, 10::32, 1::16, 23::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      assert MessageStreamer.stream_state(new_stream_state, :handler_state) == :queue.new()
      assert IO.iodata_to_binary(result) == <<?1, 4::32, original_bin::binary>>
    end

    test "multiple actions are processed in order" do
      stream_state = MessageStreamer.new_stream_state(BackendMessageHandler)

      stream_state_with_actions =
        MessageStreamer.update_state(stream_state, fn queue ->
          queue = :queue.in({:inject, :parse}, queue)

          :queue.in({:forward, :close}, queue)
        end)

      parameter_desc_bin = <<?t, 10::32, 1::16, 23::32>>
      close_bin = <<?3, 4::32>>

      {:ok, stream_state_after_param, param_result} =
        MessageStreamer.handle_packets(stream_state_with_actions, parameter_desc_bin)

      remaining_queue_after_param =
        MessageStreamer.stream_state(stream_state_after_param, :handler_state)

      assert :queue.len(remaining_queue_after_param) == 1
      assert {:value, {:forward, :close}} = :queue.peek(remaining_queue_after_param)

      assert IO.iodata_to_binary(param_result) == <<?1, 4::32, parameter_desc_bin::binary>>

      {:ok, stream_state_after_close, close_result} =
        MessageStreamer.handle_packets(stream_state_after_param, close_bin)

      remaining_queue_after_close =
        MessageStreamer.stream_state(stream_state_after_close, :handler_state)

      assert remaining_queue_after_close == :queue.new()

      assert IO.iodata_to_binary(close_result) == close_bin
    end

    test "non-matching action type is kept for later" do
      stream_state = MessageStreamer.new_stream_state(BackendMessageHandler)

      stream_state_with_action =
        MessageStreamer.update_state(stream_state, fn queue ->
          :queue.in({:intercept, :close}, queue)
        end)

      original_bin = <<?1, 4::32>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state_with_action, original_bin)

      remaining_queue = MessageStreamer.stream_state(new_stream_state, :handler_state)
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
end
