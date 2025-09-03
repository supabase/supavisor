defmodule Supavisor.Protocol.BackendMessageHandler do
  @moduledoc """
  Message handler for PostgreSQL backend messages.

  This handler processes only the messages that need special handling for prepared
  statements, namely `ParseComplete`, `CloseComplete`, and `ParameterDescription`.

  `ParseComplete` sometimes need to be intercepted (when the prepared statement was prepared
  from client's perspective, but not from ours). The same goes for `CloseComplete`. Additionally,
  `ParameterDescription` is handled because we need to inject a `ParseComplete` response
  before it when the prepared statement wasn't prepared from the client's perspective, but
  was from the server's.

  We use a queue to manage the actions that need to be performed on the messages, and actions
  may be inserted through `Supavisor.Protocol.MessageHandler.update_state/2`.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  require Supavisor.Protocol.Server, as: Server

  @impl true
  def handled_message_types do
    [?1, ?3, ?t, ?Z]
  end

  @impl true
  def init_state do
    :queue.new()
  end

  @impl true
  def handle_message(action_queue, tag, len, payload) do
    message_type = message_type(tag)
    {injected_pkts, action_queue} = maybe_inject(action_queue)

    case :queue.out(action_queue) do
      {{:value, {:intercept, ^message_type}}, updated_queue} ->
        {:ok, updated_queue, injected_pkts}

      {{:value, {:forward, ^message_type}}, updated_queue} ->
        {:ok, updated_queue, [injected_pkts, <<tag, len::32, payload::binary>>]}

      _other ->
        {:ok, action_queue, [injected_pkts, <<tag, len::32, payload::binary>>]}
    end
  end

  defp maybe_inject(action_queue) do
    case :queue.out(action_queue) do
      {{:value, {:inject, :parse}}, updated_queue} ->
        {Server.parse_complete_message(), updated_queue}

      _other ->
        {[], action_queue}
    end
  end

  defp message_type(?1), do: :parse
  defp message_type(?3), do: :close
  defp message_type(?t), do: :parameter_description
  defp message_type(?Z), do: :ready_for_query
end
