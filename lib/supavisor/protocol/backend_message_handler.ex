defmodule Supavisor.Protocol.BackendMessageHandler do
  @moduledoc """
  Message handler for PostgreSQL backend messages.

  Handles messages that need special processing:

  - `ParseComplete`, `CloseComplete`, `ParameterDescription`: prepared statement management.
    We use a queue to manage the actions that need to be performed on these messages, and
    actions may be inserted through `Supavisor.Protocol.MessageHandler.update_state/2`.
  - `ErrorResponse`: FATAL/PANIC errors are detected and stored in the handler state so the
    DbHandler can read the error reason before the connection closes.

  It also follows the backend through the frontend messages forwarded to it, so the DbHandler
  can tell when the backend has processed all of them and is idle. The frontend messages are
  queued with `expect/2` before they are sent, and each backend response consumes them the
  way the backend does:

  - Parse, Bind, Close, Describe and Execute complete with their own response.
  - Sync, Query and FunctionCall complete with `ReadyForQuery`.
  - An error in an extended protocol message makes the backend skip everything until the next
    Sync.
  - A COPY FROM STDIN makes the backend ignore Syncs until CopyDone or CopyFail.

  A Sync interleaved between CopyData messages of a COPY that then fails on bad data is
  assumed to have been ignored. Whether the backend read it before failing isn't observable.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  require Record
  require Supavisor.Protocol.Server, as: Server

  Record.defrecord(:handler_state,
    action_queue: :queue.new(),
    fatal_error: nil,
    pending: :queue.new(),
    mode: :normal,
    last_rfq_status: nil
  )

  @extended [?P, ?B, ?C, ?D, ?E]

  @impl true
  def handled_message_types do
    [?1, ?2, ?3, ?t, ?T, ?n, ?C, ?I, ?s, ?G, ?Z, ?E]
  end

  @impl true
  def init_state do
    handler_state()
  end

  @doc """
  Queues frontend messages about to be sent to the backend. `:ps` stands for a prepared
  statement packet, resolved later with `resolve_ps/3`.
  """
  def expect(state, tags) do
    pending = Enum.reduce(tags, handler_state(state, :pending), &:queue.in/2)
    handler_state(state, pending: pending)
  end

  @doc """
  Replaces the first `count` `:ps` placeholders with the messages actually sent for them.
  """
  def resolve_ps(state, count, tags) do
    {before, rest} =
      Enum.split_while(:queue.to_list(handler_state(state, :pending)), &(&1 != :ps))

    {placeholders, rest} = Enum.split(rest, count)
    true = Enum.all?(placeholders, &(&1 == :ps))
    handler_state(state, pending: :queue.from_list(before ++ tags ++ rest))
  end

  @doc """
  Whether the backend processed every queued message and is idle outside a transaction.
  """
  def synced?(state) do
    :queue.is_empty(handler_state(state, :pending)) and handler_state(state, :mode) == :normal and
      handler_state(state, :last_rfq_status) == ?I
  end

  def reset_sync(state),
    do: handler_state(state, pending: :queue.new(), mode: :normal, last_rfq_status: nil)

  @impl true
  def handle_message(state, ?E, len, payload) do
    pkt = <<?E, len::32, payload::binary>>
    error = Server.decode_error_response(payload)

    fatal = if error["S"] in ["FATAL", "PANIC"], do: error
    {:ok, state |> track(?E, payload) |> handler_state(fatal_error: fatal), pkt}
  end

  def handle_message(state, tag, len, payload) do
    state = track(state, tag, payload)
    action_queue = handler_state(state, :action_queue)
    message_type = message_type(tag)
    {injected_pkts, action_queue} = maybe_inject(action_queue)

    case :queue.out(action_queue) do
      {{:value, {:intercept, ^message_type}}, updated_queue} ->
        {:ok, handler_state(state, action_queue: updated_queue), injected_pkts}

      {{:value, {:forward, ^message_type}}, updated_queue} ->
        {:ok, handler_state(state, action_queue: updated_queue),
         [injected_pkts, <<tag, len::32, payload::binary>>]}

      _other ->
        {:ok, handler_state(state, action_queue: action_queue),
         [injected_pkts, <<tag, len::32, payload::binary>>]}
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

  defp track(state, tag, payload) do
    mode = handler_state(state, :mode)
    pending = handler_state(state, :pending)
    pending = if mode == :normal, do: drop_while(pending, &(&1 in [?c, ?f])), else: pending

    case track(mode, tag, payload, pending, :queue.peek(pending)) do
      {mode, pending, status} ->
        handler_state(state, mode: mode, pending: pending, last_rfq_status: status)

      :keep ->
        handler_state(state, pending: pending)
    end
  end

  defp track(:normal, ?Z, <<status>>, pending, head) do
    case head do
      :empty -> {:normal, pending, status}
      {:value, tag} when tag in [?S, ?Q, ?F] -> {:normal, :queue.drop(pending), status}
      _ -> {:normal, pending, nil}
    end
  end

  defp track(:normal, ?1, _, pending, {:value, ?P}), do: {:normal, :queue.drop(pending), nil}
  defp track(:normal, ?2, _, pending, {:value, ?B}), do: {:normal, :queue.drop(pending), nil}
  defp track(:normal, ?3, _, pending, {:value, ?C}), do: {:normal, :queue.drop(pending), nil}

  defp track(:normal, tag, _, pending, {:value, ?D}) when tag in [?T, ?n],
    do: {:normal, :queue.drop(pending), nil}

  defp track(:normal, tag, _, pending, {:value, ?E}) when tag in [?C, ?I, ?s],
    do: {:normal, :queue.drop(pending), nil}

  defp track(:normal, ?G, _, pending, {:value, ?E}),
    do: {{:copy_in, :extended}, :queue.drop(pending), nil}

  defp track(:normal, ?G, _, pending, {:value, ?Q}),
    do: {{:copy_in, :simple}, :queue.drop(pending), nil}

  defp track(:normal, ?E, _, pending, {:value, head}) when head in @extended,
    do: {:ignore_till_sync, :queue.drop(pending), nil}

  defp track(:ignore_till_sync, ?Z, <<status>>, pending, _head),
    do: {:normal, drop_through(pending, [?S]), status}

  defp track({:copy_in, kind}, ?C, _, pending, _head),
    do: {:normal, end_copy(kind, drop_through(pending, [?c])), nil}

  defp track({:copy_in, :extended}, ?E, _, pending, _head),
    do: {:ignore_till_sync, drop_copy_syncs(pending), nil}

  defp track({:copy_in, :simple}, ?E, _, pending, _head),
    do: {:normal, end_copy(:simple, drop_copy_syncs(pending)), nil}

  defp track(_mode, _tag, _payload, _pending, _head), do: :keep

  # A simple Query still owes its ReadyForQuery once the COPY is over.
  defp end_copy(:simple, pending), do: :queue.in_r(?Q, pending)
  defp end_copy(:extended, pending), do: pending

  # Syncs sent during copy-in were ignored, and so is the CopyDone or CopyFail after them.
  defp drop_copy_syncs(pending) do
    pending = drop_while(pending, &(&1 == ?S))

    case :queue.peek(pending) do
      {:value, tag} when tag in [?c, ?f] -> :queue.drop(pending)
      _ -> pending
    end
  end

  defp drop_through(pending, tags) do
    pending = drop_while(pending, &(&1 not in tags))
    if :queue.is_empty(pending), do: pending, else: :queue.drop(pending)
  end

  defp drop_while(pending, fun) do
    case :queue.peek(pending) do
      {:value, tag} -> if fun.(tag), do: drop_while(:queue.drop(pending), fun), else: pending
      :empty -> pending
    end
  end

  defp message_type(?1), do: :parse
  defp message_type(?3), do: :close
  defp message_type(?t), do: :parameter_description
  defp message_type(?Z), do: :ready_for_query
  defp message_type(_tag), do: :other
end
