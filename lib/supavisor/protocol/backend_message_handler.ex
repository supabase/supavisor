defmodule Supavisor.Protocol.BackendMessageHandler do
  @moduledoc """
  Message handler for PostgreSQL backend messages.

  `ErrorResponse`: FATAL/PANIC errors are detected and stored in the handler state so the
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

  Prepared statement management adds messages the client didn't send and drops some it did:

  - `{:intercept, tag}`: a Parse or Close sent by Supavisor. Its response is consumed in its
    place instead of being forwarded.
  - `:parse_complete`: a Parse not sent because the backend already has the statement. Its
    ParseComplete is emitted once every message before it has been answered, where the
    backend's own would have been.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  require Record
  require Supavisor.Protocol.Server, as: Server

  # `phase` is what the backend is doing with the messages it reads: `:normal`,
  # `:ignore_till_sync` after an error in an extended protocol message, or
  # `{:copy_in, :simple | :extended}` during a COPY FROM STDIN.
  Record.defrecord(:handler_state,
    fatal_error: nil,
    pending: :queue.new(),
    phase: :normal,
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
  statement packet, resolved later with `resolve_ps/2`.
  """
  def expect(state, tags) do
    pending = Enum.reduce(tags, handler_state(state, :pending), &:queue.in/2)
    handler_state(state, pending: pending)
  end

  @doc """
  Replaces the next `:ps` placeholders, in order, with the messages actually sent for each.

  Returns the ParseCompletes already due, for Parses not sent with nothing left to answer
  before them.
  """
  def resolve_ps(state, resolved) do
    pending = replace_placeholders(:queue.to_list(handler_state(state, :pending)), resolved, [])

    state
    |> handler_state(pending: :queue.from_list(pending))
    |> advance()
  end

  defp replace_placeholders(pending, [], acc), do: Enum.reverse(acc, pending)

  defp replace_placeholders([:ps | pending], [tags | resolved], acc),
    do: replace_placeholders(pending, resolved, Enum.reverse(tags, acc))

  defp replace_placeholders([tag | pending], resolved, acc),
    do: replace_placeholders(pending, resolved, [tag | acc])

  @doc """
  Whether the backend processed every queued message and is idle outside a transaction.
  """
  def synced?(state) do
    :queue.is_empty(handler_state(state, :pending)) and handler_state(state, :phase) == :normal and
      handler_state(state, :last_rfq_status) == ?I
  end

  @doc """
  Like `synced?/1`, but consumes the ReadyForQuery that synced it, so a later chunk without
  one can't report the same batch as synced again.
  """
  def take_synced(state), do: {synced?(state), handler_state(state, last_rfq_status: nil)}

  def reset_sync(state),
    do: handler_state(state, pending: :queue.new(), phase: :normal, last_rfq_status: nil)

  @impl true
  def handle_message(state, ?E, len, payload) do
    pkt = <<?E, len::32, payload::binary>>
    error = Server.decode_error_response(payload)

    fatal = if error["S"] in ["FATAL", "PANIC"], do: error
    {state, before, _intercepted?, after_pkts} = track(state, ?E, payload)
    {:ok, handler_state(state, fatal_error: fatal), [before, pkt, after_pkts]}
  end

  def handle_message(state, tag, len, payload) do
    {state, before, intercepted?, after_pkts} = track(state, tag, payload)
    pkt = if intercepted?, do: [], else: <<tag, len::32, payload::binary>>
    {:ok, state, [before, pkt, after_pkts]}
  end

  defp track(state, tag, payload) do
    {state, before} = advance(state)
    phase = handler_state(state, :phase)
    pending = handler_state(state, :pending)
    head = :queue.peek(pending)
    intercepted? = intercepted?(phase, tag, head)

    state =
      case step(phase, tag, payload, pending, sent_tag(head)) do
        {phase, pending, status} ->
          handler_state(state, phase: phase, pending: pending, last_rfq_status: status)

        :keep ->
          state
      end

    {state, after_pkts} = advance(state)
    {state, before, intercepted?, after_pkts}
  end

  # The response to a Parse or Close sent by Supavisor, which the client must not see.
  defp intercepted?(:normal, ?1, {:value, {:intercept, ?P}}), do: true
  defp intercepted?(:normal, ?3, {:value, {:intercept, ?C}}), do: true
  defp intercepted?(_phase, _tag, _head), do: false

  defp sent_tag({:value, {:intercept, tag}}), do: {:value, tag}
  defp sent_tag(head), do: head

  # In the normal phase, CopyDone and CopyFail are ignored by the backend, and a Parse that
  # wasn't sent is answered as soon as it's next.
  #
  # Only a ReadyForQuery can leave the backend synced. A ParseComplete answered after it
  # belongs to a new extended protocol batch, still waiting for its Sync.
  defp advance(state) do
    if handler_state(state, :phase) == :normal,
      do: advance(state, handler_state(state, :pending), []),
      else: {state, []}
  end

  defp advance(state, pending, pkts) do
    case :queue.peek(pending) do
      {:value, tag} when tag in [?c, ?f] ->
        advance(state, :queue.drop(pending), pkts)

      {:value, :parse_complete} ->
        state = handler_state(state, last_rfq_status: nil)
        advance(state, :queue.drop(pending), [Server.parse_complete_message() | pkts])

      _ ->
        {handler_state(state, pending: pending), Enum.reverse(pkts)}
    end
  end

  # Moves the backend past the messages a response completes. Returns the new phase, the
  # messages still pending and the ReadyForQuery status, or `:keep` when the response
  # completes none.
  defp step(:normal, ?Z, <<status>>, pending, head) do
    case head do
      :empty -> {:normal, pending, status}
      {:value, tag} when tag in [?S, ?Q, ?F] -> {:normal, :queue.drop(pending), status}
      _ -> {:normal, pending, nil}
    end
  end

  defp step(:normal, ?1, _, pending, {:value, ?P}), do: {:normal, :queue.drop(pending), nil}
  defp step(:normal, ?2, _, pending, {:value, ?B}), do: {:normal, :queue.drop(pending), nil}
  defp step(:normal, ?3, _, pending, {:value, ?C}), do: {:normal, :queue.drop(pending), nil}

  defp step(:normal, tag, _, pending, {:value, ?D}) when tag in [?T, ?n],
    do: {:normal, :queue.drop(pending), nil}

  defp step(:normal, tag, _, pending, {:value, ?E}) when tag in [?C, ?I, ?s],
    do: {:normal, :queue.drop(pending), nil}

  defp step(:normal, ?G, _, pending, {:value, ?E}),
    do: {{:copy_in, :extended}, :queue.drop(pending), nil}

  defp step(:normal, ?G, _, pending, {:value, ?Q}),
    do: {{:copy_in, :simple}, :queue.drop(pending), nil}

  defp step(:normal, ?E, _, pending, {:value, head}) when head in @extended,
    do: {:ignore_till_sync, :queue.drop(pending), nil}

  defp step(:ignore_till_sync, ?Z, <<status>>, pending, _head),
    do: {:normal, drop_through(pending, [?S]), status}

  defp step({:copy_in, kind}, ?C, _, pending, _head),
    do: {:normal, end_copy(kind, drop_through(pending, [?c])), nil}

  defp step({:copy_in, :extended}, ?E, _, pending, _head),
    do: {:ignore_till_sync, drop_copy_syncs(pending), nil}

  defp step({:copy_in, :simple}, ?E, _, pending, _head),
    do: {:normal, end_copy(:simple, drop_copy_syncs(pending)), nil}

  defp step(_phase, _tag, _payload, _pending, _head), do: :keep

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
end
