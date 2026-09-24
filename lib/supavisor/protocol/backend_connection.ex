defmodule Supavisor.Protocol.BackendConnection do
  @moduledoc """
  A pure model of a backend connection: the frontend messages the backend still has to
  answer, what it's doing with the messages it reads, and the prepared statements it has.

  The DbHandler drives it with:

  - `sent/2`: the ClientHandler is writing these messages straight to the backend socket.
    A write with prepared statement packets (`{:ps, tag}`) is parked until `write/2`.
  - `write/2`: the parked write, which goes through the DbHandler. What is actually sent for
    each prepared statement packet depends on the statements the backend has.
  - `query/2`: a query Supavisor runs for itself. None of its responses reach the client.
  - `evict/2`: closes statements to make room for new ones.
  - `recv/2`: bytes from the backend. Returns what to forward to the client, and whether the
    backend became idle with every message answered.

  ## States

  - `:idle`: every message answered, outside a transaction.
  - `:in_transaction`: every message answered, inside a transaction block.
  - `:busy`: waiting for responses.
  - `:ignore_till_sync`: an extended protocol message failed, so the backend skips everything
    until the next Sync.
  - `{:copy_in, :simple | :extended}`: a COPY FROM STDIN, during which the backend ignores
    Syncs until CopyDone or CopyFail.

  A Sync interleaved between CopyData messages of a COPY that then fails on bad data is
  assumed to have been ignored. Whether the backend read it before failing isn't observable.

  ## Queue

  Each message the backend still has to answer is queued as `{message, disposition, name}`,
  `name` being the prepared statement it creates or closes:

  - `:forward`: sent by the client, its responses go to the client.
  - `:intercept`: a Parse or Close sent by Supavisor to manage prepared statements. Its
    ParseComplete or CloseComplete is consumed. An error goes to the client, since its next
    messages depended on it.
  - `:synthesize`: a Parse not sent because the backend already has the statement, or a Close
    not sent because it doesn't. Its ParseComplete or CloseComplete is made up once every
    message before it has been answered.
  - `:internal`: part of a `query/2`. Every response is consumed.

  ## Prepared statements

  A statement is recorded when its Parse is sent, so later packets see it, and forgotten when
  its Close is sent. If the backend fails the Parse or skips either message, that is undone.
  Packets sent before the backend's answer arrives may still fail with it, since whether it
  would succeed wasn't known when they were sent.
  """

  require Record
  require Supavisor.Protocol.Server, as: Server

  alias Supavisor.Protocol.PreparedStatements

  Record.defrecord(:backend,
    state: :idle,
    queue: :queue.new(),
    announced: nil,
    storage: nil,
    statements: nil,
    fatal_error: nil,
    buffer: <<>>,
    in_flight: nil
  )

  @type state() ::
          :idle | :in_transaction | :busy | :ignore_till_sync | {:copy_in, :simple | :extended}

  @type message() ::
          :parse
          | :bind
          | :close
          | :describe
          | :execute
          | :sync
          | :query
          | :function_call
          | :copy_done
          | :copy_fail

  @type entry() ::
          {message(), :forward | :intercept | :synthesize | :internal,
           PreparedStatements.statement_name() | nil}

  @type t() ::
          record(:backend,
            state: state(),
            queue: :queue.queue(entry()),
            announced: [byte() | {:ps, byte()}] | nil,
            storage: module(),
            statements: term(),
            fatal_error: map() | nil,
            buffer: binary(),
            in_flight: {non_neg_integer(), forward? :: boolean()} | nil
          )

  @tracked [?1, ?2, ?3, ?T, ?n, ?C, ?I, ?s, ?G, ?Z, ?E]
  @extended [:parse, :bind, :close, :describe, :execute]

  defguardp answering(state) when state in [:idle, :in_transaction, :busy]

  @spec new(module()) :: t()
  def new(storage), do: backend(storage: storage, statements: storage.new())

  @spec fatal_error(t()) :: map() | nil
  def fatal_error(backend(fatal_error: error)), do: error

  @doc """
  Records the messages of a client write, in order, before they reach the backend.
  """
  @spec sent(t(), [byte() | {:ps, byte()}]) :: t()
  def sent(backend(announced: nil) = t, tags) do
    if Enum.any?(tags, &match?({:ps, _}, &1)) do
      backend(t, announced: tags)
    else
      {t, []} = t |> enqueue(Enum.map(tags, &forwarded/1)) |> advance()
      t
    end
  end

  @doc """
  Decides what is sent for the parked write's packets.

  Returns what to send to the backend, the ParseCompletes already due to the client, and how
  many statements were evicted to make room.
  """
  @spec write(t(), [binary() | PreparedStatements.handled_pkt()]) ::
          {t(), iodata(), iodata(), non_neg_integer()}
  def write(backend(announced: announced, storage: storage) = t, pkts) when is_list(announced) do
    limit = PreparedStatements.backend_limit()
    statements = backend(t, :statements)

    # Room is made before the packets are decided, so the write sends a Parse again for any
    # statement it needs that was closed.
    {evicted, statements} =
      if storage.size(statements) >= limit,
        do: storage.evict(statements, div(limit, 5)),
        else: {[], statements}

    closes =
      {Enum.map(evicted, &PreparedStatements.build_close_pkt/1),
       Enum.map(evicted, &{:close, :intercept, &1})}

    {sent, prepared, statements, _closes} =
      Enum.reduce(pkts, {[], [], statements, closes}, &prepare(&1, &2, storage))

    entries = substitute(announced, Enum.reverse(prepared), [])

    {t, due} =
      t
      |> backend(announced: nil, statements: statements)
      |> enqueue(entries)
      |> advance()

    {t, Enum.reverse(sent), due, length(evicted)}
  end

  @doc """
  Closes up to `count` statements, picked by the storage.

  Returns the Closes to send and how many statements they close. Their responses are only
  flushed by a later Sync or Flush.
  """
  @spec evict(t(), pos_integer()) :: {t(), iodata(), non_neg_integer()}
  def evict(backend(storage: storage, statements: statements) = t, count) do
    {evicted, statements} = storage.evict(statements, count)

    t =
      t
      |> backend(statements: statements)
      |> enqueue(Enum.map(evicted, &{:close, :intercept, &1}))

    {t, Enum.map(evicted, &PreparedStatements.build_close_pkt/1), length(evicted)}
  end

  @doc """
  Records a query Supavisor is about to send for itself.
  """
  @spec query(t(), iodata()) :: t()
  def query(t, msgs), do: enqueue(t, internal(IO.iodata_to_binary(msgs), []))

  @doc """
  Follows the backend through its messages.

  Returns what to forward to the client, and whether the backend became idle, outside a
  transaction, with every message answered and no write parked.
  """
  @spec recv(t(), binary()) :: {t(), iodata(), boolean()}
  def recv(backend(buffer: buffer) = t, bin) do
    {t, out, synced?} = frame(backend(t, buffer: <<>>), buffer <> bin, [], false)
    {t, Enum.reverse(out), synced?}
  end

  defp prepare(bin, {sent, prepared, statements, closes}, _storage) when is_binary(bin),
    do: {[bin | sent], prepared, statements, closes}

  # The Closes go right before the first prepared statement packet. The client only sends it
  # where the backend accepts it, e.g. not during a COPY, and whatever ends its batch flushes
  # their responses too.
  defp prepare(pkt, {sent, prepared, statements, {close_pkts, close_entries}}, storage) do
    {tag, bins, entries, statements} = prepare_pkt(pkt, statements, storage)

    {Enum.reverse(close_pkts ++ bins, sent), [{tag, close_entries ++ entries} | prepared],
     statements, {[], []}}
  end

  defp prepare_pkt({type, name, pkt, parse_pkt}, statements, storage)
       when type in [:bind_pkt, :describe_pkt] do
    {tag, message} = if type == :bind_pkt, do: {?B, :bind}, else: {?D, :describe}

    if storage.member?(statements, name) do
      {tag, [pkt], [{message, :forward, nil}], storage.touch(statements, name)}
    else
      {tag, [parse_pkt, pkt], [{:parse, :intercept, name}, {message, :forward, nil}],
       storage.put(statements, name)}
    end
  end

  defp prepare_pkt({:parse_pkt, name, pkt}, statements, storage) do
    if storage.member?(statements, name) do
      {?P, [], [{:parse, :synthesize, name}], storage.touch(statements, name)}
    else
      {?P, [pkt], [{:parse, :forward, name}], storage.put(statements, name)}
    end
  end

  defp prepare_pkt({:close_pkt, name, pkt}, statements, storage) do
    if storage.member?(statements, name) do
      {?C, [pkt], [{:close, :forward, name}], storage.delete(statements, name)}
    else
      {?C, [], [{:close, :synthesize, name}], statements}
    end
  end

  defp substitute([{:ps, tag} | tags], [{tag, entries} | prepared], acc),
    do: substitute(tags, prepared, Enum.reverse(entries, acc))

  defp substitute([tag | tags], prepared, acc) when is_integer(tag),
    do: substitute(tags, prepared, [forwarded(tag) | acc])

  defp substitute([], [], acc), do: Enum.reverse(acc)

  defp internal(<<tag, len::32, _::binary-size(len - 4), rest::binary>>, acc) do
    case message(tag) do
      nil -> internal(rest, acc)
      message -> internal(rest, [{message, :internal, nil} | acc])
    end
  end

  defp internal(<<>>, acc), do: Enum.reverse(acc)

  defp forwarded(tag), do: {message(tag) || raise("untracked message #{<<tag>>}"), :forward, nil}

  defp message(?P), do: :parse
  defp message(?B), do: :bind
  defp message(?C), do: :close
  defp message(?D), do: :describe
  defp message(?E), do: :execute
  defp message(?S), do: :sync
  defp message(?Q), do: :query
  defp message(?F), do: :function_call
  defp message(?c), do: :copy_done
  defp message(?f), do: :copy_fail
  defp message(_tag), do: nil

  defp enqueue(t, []), do: t

  defp enqueue(backend(state: state, queue: queue) = t, entries) do
    state = if answering(state), do: :busy, else: state
    backend(t, state: state, queue: :queue.join(queue, :queue.from_list(entries)))
  end

  # The backend ignores CopyDone and CopyFail outside a COPY, and a Parse or Close that wasn't
  # sent is answered as soon as it's next. Its response belongs to a new extended protocol
  # batch, still waiting for its Sync.
  defp advance(backend(state: state, queue: queue) = t) when answering(state),
    do: advance(t, queue, [])

  defp advance(t), do: {t, []}

  defp advance(t, queue, due) do
    case :queue.peek(queue) do
      {:value, {message, _, _}} when message in [:copy_done, :copy_fail] ->
        advance(t, :queue.drop(queue), due)

      {:value, {:parse, :synthesize, _}} ->
        advance(backend(t, state: :busy), :queue.drop(queue), [
          Server.parse_complete_message() | due
        ])

      {:value, {:close, :synthesize, _}} ->
        advance(backend(t, state: :busy), :queue.drop(queue), [
          Server.close_complete_message() | due
        ])

      _ ->
        {backend(t, queue: queue), Enum.reverse(due)}
    end
  end

  defp frame(backend(in_flight: {remaining, forward?}) = t, bin, out, synced?) do
    case bin do
      <<part::binary-size(remaining), rest::binary>> ->
        frame(backend(t, in_flight: nil), rest, keep(out, forward?, part), synced?)

      part ->
        in_flight = {remaining - byte_size(part), forward?}
        {backend(t, in_flight: in_flight), keep(out, forward?, part), synced?}
    end
  end

  defp frame(t, <<tag, len::32, payload::binary-size(len - 4), rest::binary>> = bin, out, synced?)
       when tag in @tracked do
    {t, out} = handle(t, tag, payload, binary_part(bin, 0, len + 1), out)
    frame(t, rest, out, synced? or (tag == ?Z and synced?(t)))
  end

  # Messages that don't move the backend along, like DataRow, are streamed through without
  # waiting for the whole message.
  defp frame(t, <<tag, len::32, _::binary>> = bin, out, synced?) when tag not in @tracked,
    do: frame(backend(t, in_flight: {len + 1, not internal_head?(t)}), bin, out, synced?)

  defp frame(t, <<>>, out, synced?), do: {t, out, synced?}
  defp frame(t, partial, out, synced?), do: {backend(t, buffer: partial), out, synced?}

  # A parked write is on its way to the backend, so it isn't done yet.
  defp synced?(backend(state: state, announced: announced)),
    do: state == :idle and announced == nil

  defp keep(out, true, part), do: [part | out]
  defp keep(out, false, _part), do: out

  defp handle(t, tag, payload, pkt, out) do
    t = if tag == ?E, do: record_fatal(t, payload), else: t
    forward? = forward?(t, tag)
    {t, due} = t |> step(tag, payload) |> advance()
    {t, Enum.reverse(due, keep(out, forward?, pkt))}
  end

  defp record_fatal(t, payload) do
    error = Server.decode_error_response(payload)
    if error["S"] in ["FATAL", "PANIC"], do: backend(t, fatal_error: error), else: t
  end

  defp forward?(backend(state: state, queue: queue) = t, tag) do
    case {tag, :queue.peek(queue)} do
      {?1, {:value, {:parse, :intercept, _}}} when answering(state) -> false
      {?3, {:value, {:close, :intercept, _}}} when answering(state) -> false
      _ -> not internal_head?(t)
    end
  end

  defp internal_head?(backend(queue: queue)),
    do: match?({:value, {_, :internal, _}}, :queue.peek(queue))

  defp step(backend(state: state, queue: queue) = t, ?Z, <<status>>) when answering(state) do
    case :queue.peek(queue) do
      :empty ->
        ready(t, status)

      {:value, {message, _, _}} when message in [:sync, :query, :function_call] ->
        ready(pop(t), status)

      _ ->
        t
    end
  end

  defp step(backend(state: state, queue: queue) = t, tag, _payload) when answering(state) do
    case {tag, :queue.peek(queue)} do
      {?1, {:value, {:parse, _, _}}} ->
        pop(t)

      {?2, {:value, {:bind, _, _}}} ->
        pop(t)

      {?3, {:value, {:close, _, _}}} ->
        pop(t)

      {tag, {:value, {:describe, _, _}}} when tag in [?T, ?n] ->
        pop(t)

      {tag, {:value, {:execute, _, _}}} when tag in [?C, ?I, ?s] ->
        pop(t)

      {?G, {:value, {:execute, _, _}}} ->
        backend(pop(t), state: {:copy_in, :extended})

      {?G, {:value, {:query, _, _}}} ->
        backend(pop(t), state: {:copy_in, :simple})

      {?E, {:value, {message, _, _}}} when message in @extended ->
        backend(skip(t), state: :ignore_till_sync)

      _ ->
        t
    end
  end

  defp step(backend(state: :ignore_till_sync) = t, ?Z, <<status>>),
    do: t |> skip_through(:sync) |> ready(status)

  defp step(backend(state: {:copy_in, kind}) = t, ?C, _payload),
    do: t |> skip_through(:copy_done) |> end_copy(kind)

  defp step(backend(state: {:copy_in, :extended}) = t, ?E, _payload),
    do: backend(skip_copy_syncs(t), state: :ignore_till_sync)

  defp step(backend(state: {:copy_in, :simple}) = t, ?E, _payload),
    do: t |> skip_copy_syncs() |> end_copy(:simple)

  defp step(t, _tag, _payload), do: t

  defp ready(backend(queue: queue) = t, status) do
    state =
      cond do
        not :queue.is_empty(queue) -> :busy
        status == ?I -> :idle
        true -> :in_transaction
      end

    backend(t, state: state)
  end

  # A simple Query still owes its ReadyForQuery once the COPY is over.
  defp end_copy(backend(queue: queue) = t, :simple),
    do: backend(t, state: :busy, queue: :queue.in_r({:query, :forward, nil}, queue))

  defp end_copy(t, :extended), do: backend(t, state: :busy)

  # Syncs sent during copy-in were ignored, and so is the CopyDone or CopyFail after them.
  defp skip_copy_syncs(backend(queue: queue) = t) do
    case :queue.peek(queue) do
      {:value, {:sync, _, _}} -> t |> skip() |> skip_copy_syncs()
      {:value, {message, _, _}} when message in [:copy_done, :copy_fail] -> skip(t)
      _ -> t
    end
  end

  defp skip_through(backend(queue: queue) = t, message) do
    case :queue.peek(queue) do
      {:value, {^message, _, _}} -> skip(t)
      {:value, _} -> t |> skip() |> skip_through(message)
      :empty -> t
    end
  end

  defp pop(backend(queue: queue) = t), do: backend(t, queue: :queue.drop(queue))

  # The backend didn't carry out the message at the head, so its effect on the statements
  # it has is undone.
  defp skip(backend(queue: queue, storage: storage, statements: statements) = t) do
    {{:value, entry}, queue} = :queue.out(queue)

    statements =
      case entry do
        {:parse, disposition, name}
        when disposition in [:forward, :intercept] and is_binary(name) ->
          storage.delete(statements, name)

        {:close, disposition, name}
        when disposition in [:forward, :intercept] and is_binary(name) ->
          storage.put(statements, name)

        _ ->
          statements
      end

    backend(t, queue: queue, statements: statements)
  end
end
