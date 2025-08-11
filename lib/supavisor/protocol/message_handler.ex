defmodule Supavisor.Protocol.MessageHandler do
  @moduledoc """
  Behaviour for handling PostgreSQL protocol messages in a streaming context.

  Message handlers can specify which message types they're interested in and
  implement the logic for processing those messages.
  """

  @doc """
  Returns a list of message tags (bytes) that this handler processes.

  Only messages with these tags will be passed to handle_message/4.
  """
  @callback handled_message_types() :: [byte()]

  @doc """
  Initializes the handler's state.
  """
  @callback init_state() :: any()

  @doc """
  Handles a message that matches one of the interested message types.

  ## Parameters
  - `handler_state`: The current state of the handler
  - `tag`: The message tag (byte)
  - `len`: The message length
  - `payload`: The message payload

  ## Returns
  - `{:ok, new_handler_state, output_packet}`: Success with new state and output
  - `{:error, reason}`: Error with reason

  The `output_packet` can be either a binary (raw packet) or a tuple representing
  a special packet type that needs further processing.
  """
  @callback handle_message(
              handler_state :: any(),
              tag :: byte(),
              len :: non_neg_integer(),
              payload :: binary()
            ) ::
              {:ok, new_handler_state :: any(), output_packet :: iodata() | tuple()}
              | {:error, reason :: any()}
end
