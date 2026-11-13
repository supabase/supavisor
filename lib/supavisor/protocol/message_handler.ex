defmodule Supavisor.Protocol.MessageHandler do
  @moduledoc """
  Behaviour for handling PostgreSQL protocol messages in a streaming context.

  Message handlers can specify which message types they're interested in and
  implement the logic for processing those messages.
  """

  @doc """
  Returns a list of message tags (bytes) that this handler processes.

  Only messages with these tags will be passed to handle_message/4, or to
  handle_streamed/2 when handle_partial/3 chose to stream them.
  """
  @callback handled_message_types() :: [byte()]

  @doc """
  Initializes the handler's state.
  """
  @callback init_state() :: any()

  @doc """
  Called when a message of an interested type arrives incomplete. `:buffer` holds it until
  complete and then passes it to `handle_message/4`. `:stream` forwards it as it arrives, and
  calls `handle_streamed/2` instead once its last byte has been forwarded.
  """
  @callback handle_partial(handler_state :: any(), tag :: byte(), len :: non_neg_integer()) ::
              :buffer | :stream

  @doc """
  Called once the last byte of a message `handle_partial/3` chose to stream has been forwarded.
  """
  @callback handle_streamed(handler_state :: any(), tag :: byte()) :: new_handler_state :: any()

  @doc """
  Handles a message that matches one of the interested message types.
  """
  @callback handle_message(
              handler_state :: any(),
              tag :: byte(),
              len :: non_neg_integer(),
              payload :: binary()
            ) ::
              {:ok, new_handler_state :: any(), output_packet :: iodata() | tuple()}
              | {:error, reason :: atom()}
              | {:error, reason :: atom(), details :: term()}
end
