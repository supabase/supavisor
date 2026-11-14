defmodule Supavisor.Protocol.MessageStreamer do
  @moduledoc """
  Handles streaming PostgreSQL protocol messages and delegates to a message handler.

  This module handles the low-level packet parsing, buffering, and streaming logic,
  while delegating actual message processing to a handler that implements the
  MessageHandler behaviour.
  """

  require Record

  Record.defrecord(
    :stream_state,
    handler_module: nil,
    handler_state: nil,
    pending_bin: <<>>,
    pending_msg: nil,
    pkts: [],
    in_flight_pkt: nil,
    handle_streamed?: false
  )

  @type stream_state() ::
          record(:stream_state,
            handler_module: module(),
            handler_state: any(),
            pending_bin: binary(),
            pending_msg: {remaining_len :: pos_integer(), iodata()} | nil,
            pkts: [binary() | tuple()],
            in_flight_pkt: {tag :: binary(), remaining_len :: non_neg_integer()} | nil,
            # Whether the message in flight is one handle_partial/3 chose to stream, so
            # handle_streamed/2 is due when it completes.
            handle_streamed?: boolean()
          )

  @type pkt() :: binary()

  @doc """
  Creates a new stream state with the given handler module.
  """
  @spec new_stream_state(module()) :: stream_state()
  def new_stream_state(handler_module) do
    stream_state(
      handler_module: handler_module,
      handler_state: handler_module.init_state(),
      pending_bin: <<>>,
      pending_msg: nil,
      pkts: [],
      in_flight_pkt: nil,
      handle_streamed?: false
    )
  end

  @doc """
  Handles incoming packet data and returns processed packets.

  Errors are dependent on the message handler implementation
  """
  @spec handle_packets(stream_state(), pkt()) ::
          {:ok, stream_state(), [pkt() | tuple()]}
          | {:error, atom()}
          | {:error, atom(), term()}
  def handle_packets(acc, binary) do
    case do_handle_packets(acc, binary) do
      {:ok, acc} ->
        {:ok, stream_state(acc, pkts: []), Enum.reverse(stream_state(acc, :pkts))}

      error ->
        error
    end
  end

  defp do_handle_packets(acc, binary) do
    case acc do
      stream_state(in_flight_pkt: {_tag, _len}) ->
        handle_in_flight(acc, binary)

      stream_state(pending_msg: {_remaining_len, _chunks}) ->
        handle_pending_msg(acc, binary)

      stream_state(pending_bin: "") ->
        handle_pkt(acc, binary)

      stream_state(pending_bin: pending_bin) ->
        handle_pkt(stream_state(acc, pending_bin: ""), pending_bin <> binary)
    end
  end

  defp handle_in_flight(acc, binary) do
    {tag, remaining_len} = stream_state(acc, :in_flight_pkt)

    case binary do
      # Message is complete
      <<rest_of_message::binary-size(remaining_len), rest::binary>> ->
        handler_state = stream_state(acc, :handler_state)

        handler_state =
          if stream_state(acc, :handle_streamed?),
            do: stream_state(acc, :handler_module).handle_streamed(handler_state, tag),
            else: handler_state

        new_stream_state =
          stream_state(acc,
            pkts: [rest_of_message | stream_state(acc, :pkts)],
            handler_state: handler_state,
            in_flight_pkt: nil,
            handle_streamed?: false
          )

        do_handle_packets(new_stream_state, rest)

      # Message is incomplete, continue in flight
      rest_of_message ->
        new_stream_state =
          stream_state(acc,
            pkts: [rest_of_message | stream_state(acc, :pkts)],
            in_flight_pkt: {tag, remaining_len - byte_size(rest_of_message)}
          )

        {:ok, new_stream_state}
    end
  end

  # Chunks of a handled message are kept as iodata and joined once the message is
  # complete, so each read costs its own size rather than the size buffered so far.
  defp handle_pending_msg(acc, binary) do
    {remaining_len, chunks} = stream_state(acc, :pending_msg)

    case binary do
      <<last_chunk::binary-size(remaining_len), rest::binary>> ->
        msg = IO.iodata_to_binary([chunks, last_chunk])

        with {:ok, acc} <- handle_pkt(stream_state(acc, pending_msg: nil), msg) do
          do_handle_packets(acc, rest)
        end

      chunk ->
        {:ok,
         stream_state(acc,
           pending_msg: {remaining_len - byte_size(chunk), [chunks, chunk]}
         )}
    end
  end

  defp handle_pkt(acc, binary) do
    case binary do
      <<tag, len::32, payload::binary-size(len - 4), rest::binary>> ->
        case handle_message(acc, tag, len, payload) do
          {:ok, new_handler_state, pkt} ->
            do_handle_packets(
              stream_state(acc,
                pkts: [pkt | stream_state(acc, :pkts)],
                handler_state: new_handler_state
              ),
              rest
            )

          err ->
            err
        end

      # Incomplete message with known len
      <<tag, len::32, _rest::binary>> = bin ->
        handler_module = stream_state(acc, :handler_module)
        handled? = tag in handler_module.handled_message_types()

        partial =
          if handled?,
            do: handler_module.handle_partial(stream_state(acc, :handler_state), tag, len),
            else: :stream

        case partial do
          :buffer ->
            {:ok, stream_state(acc, pending_msg: {len + 1 - byte_size(bin), bin})}

          :stream ->
            {:ok,
             stream_state(acc,
               pkts: [bin | stream_state(acc, :pkts)],
               in_flight_pkt: {tag, len + 1 - byte_size(bin)},
               handle_streamed?: handled?
             )}
        end

      # Incomplete message
      bin ->
        {:ok, stream_state(acc, pending_bin: bin)}
    end
  end

  defp handle_message(acc, tag, len, payload) do
    handler_module = stream_state(acc, :handler_module)
    handler_state = stream_state(acc, :handler_state)
    handled_message_types = handler_module.handled_message_types()

    if tag in handled_message_types do
      handler_module.handle_message(handler_state, tag, len, payload)
    else
      # Pass through unchanged for messages we're not interested in
      {:ok, handler_state, <<tag, len::32, payload::binary>>}
    end
  end

  def update_state(acc, fun) do
    new_handler_state = fun.(stream_state(acc, :handler_state))
    stream_state(acc, handler_state: new_handler_state)
  end
end
