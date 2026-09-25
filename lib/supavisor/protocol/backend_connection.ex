defmodule Supavisor.Protocol.BackendConnection do
  @moduledoc """
  A pure model of a backend connection: the requests the backend still has to answer, what it
  does with the messages it reads, and the prepared statements it has.

  The DbHandler drives it with:

  - `client_write/2`: the ClientHandler is writing these messages straight to the backend
    socket. A write with prepared statement packets (`{:ps, tag}`) is parked until
    `send_parked_write/2`.
  - `send_parked_write/2`: the parked write, which goes through the DbHandler. What is
    actually sent for each prepared statement packet depends on the statements the backend
    has.
  - `query/2`: a query Supavisor runs for itself. None of its responses reach the client.
  - `recv/2`: bytes from the backend. Returns what to forward to the client, and whether the
    backend became idle with every request answered.

  ## States

  - `:idle`: every request answered, outside a transaction.
  - `:in_transaction`: every request answered, inside a transaction block.
  - `:busy`: waiting for responses.
  - `:ignore_till_sync`: an extended query message failed, so the backend ignores every
    message until the next Sync.
  - `{:copy_in, :simple | :extended}`: a COPY FROM STDIN, during which the backend ignores
    Syncs until CopyDone or CopyFail.

  In `:idle`, `:in_transaction` and `:busy`, the backend answers each message in turn.

  A COPY that fails on bad data is over for the backend, but not for the client, which keeps
  sending CopyData until its CopyDone or CopyFail. The backend isn't synced until that arrives.

  A Sync interleaved between CopyData messages of a COPY that then fails on bad data is
  assumed to have been ignored. Whether the backend read it before failing isn't observable.

  ## Requests

  Each message the backend still has to answer is queued as a request,
  `{message, action, name}`. `name` is the prepared statement it uses, creates or closes. The
  action says what happens to its responses:

  - `:forward`: sent by the client. Its responses go to the client.
  - `:skip`: a Parse or Close sent by Supavisor to manage prepared statements. Its
    ParseComplete or CloseComplete is dropped. An error goes to the client, since its next
    messages depended on it.
  - `:fake`: a Parse not sent because the backend already has the statement, or a Close
    not sent because it doesn't. Its ParseComplete or CloseComplete is made up once every
    request before it has been answered.
  - `:internal`: part of a `query/2`. Every response is dropped.

  ## Prepared statements

  A statement is recorded when its Parse is sent, so later packets see it, and forgotten when
  its Close is sent. If the backend fails the Parse or ignores either message, that is undone.
  Packets sent before the backend's answer arrives may still fail with it, since whether it
  would succeed wasn't known when they were sent.

  Undoing each ignored message on its own can leave the record wrong when a statement has
  more than one unanswered Parse or Close. The backend's next error about the statement
  corrects it. A Parse failing with 42P05 records the statement, and a Bind or Describe
  failing with 26000 forgets it.
  """

  require Record
  require Supavisor.Protocol.Server, as: Server

  alias Supavisor.Protocol.PreparedStatements

  Record.defrecord(:backend,
    state: :idle,
    requests: :queue.new(),
    parked_write: nil,
    storage: nil,
    statements: nil,
    fatal_error: nil,
    buffer: <<>>,
    streaming: nil,
    client_in_copy: false
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

  @type action() :: :forward | :skip | :fake | :internal

  @type request() :: {message(), action(), PreparedStatements.statement_name() | nil}

  @type t() ::
          record(:backend,
            state: state(),
            requests: :queue.queue(request()),
            parked_write: [byte() | {:ps, byte()}] | nil,
            storage: module(),
            statements: term(),
            fatal_error: map() | nil,
            buffer: binary(),
            streaming: {bytes_left :: non_neg_integer(), forward? :: boolean()} | nil,
            client_in_copy: boolean()
          )

  @parse_complete ?1
  @bind_complete ?2
  @close_complete ?3
  @row_description ?T
  @no_data ?n
  @command_complete ?C
  @empty_query_response ?I
  @portal_suspended ?s
  @copy_in_response ?G
  @ready_for_query ?Z
  @error_response ?E

  # Any other backend message, like DataRow, doesn't move the backend along.
  @tracked_messages [
    @parse_complete,
    @bind_complete,
    @close_complete,
    @row_description,
    @no_data,
    @command_complete,
    @empty_query_response,
    @portal_suspended,
    @copy_in_response,
    @ready_for_query,
    @error_response
  ]

  @extended_query_messages [:parse, :bind, :close, :describe, :execute]

  @duplicate_pstatement "42P05"
  @undefined_pstatement "26000"

  defguardp is_answering(state) when state in [:idle, :in_transaction, :busy]

  @spec new(module()) :: t()
  def new(storage),
    do: backend(storage: storage, statements: storage.new(), requests: :queue.new())

  @spec fatal_error(t()) :: map() | nil
  def fatal_error(backend(fatal_error: error)), do: error

  @doc """
  Records the messages of a client write, in order, before they reach the backend.
  """
  @spec client_write(t(), [byte() | {:ps, byte()}]) :: t()
  def client_write(backend(parked_write: nil) = backend, tags) do
    {backend, tags} = drop_copy_end(backend, tags)

    if Enum.any?(tags, &match?({:ps, _}, &1)) do
      backend(backend, parked_write: tags)
    else
      {backend, []} =
        backend |> add_requests(Enum.map(tags, &client_request/1)) |> pop_unanswered()

      backend
    end
  end

  @doc """
  Decides what is sent for the parked write's packets.

  Returns what to send to the backend, the responses already due to the client, and how many
  statements were evicted to make room.
  """
  @spec send_parked_write(t(), [binary() | PreparedStatements.handled_pkt()]) ::
          {t(), iodata(), iodata(), non_neg_integer()}
  def send_parked_write(
        backend(parked_write: tags, storage: storage, statements: statements) = backend,
        pkts
      )
      when is_list(tags) do
    limit = PreparedStatements.backend_limit()

    # Room is made before the packets are decided, so the write sends a Parse again for any
    # statement it needs that was evicted.
    {evicted, statements} =
      if storage.size(statements) >= limit,
        do: storage.evict(statements, div(limit, 5)),
        else: {[], statements}

    # The Closes go right before the first prepared statement packet. The client only sends it
    # where the backend accepts it, e.g. not during a COPY, and whatever ends its batch flushes
    # their responses too.
    {plain_pkts, pkts} = Enum.split_while(pkts, &is_binary/1)
    {plain_tags, tags} = Enum.split_while(tags, &is_integer/1)
    close_pkts = Enum.map(evicted, &PreparedStatements.build_close_pkt/1)
    close_requests = Enum.map(evicted, &{:close, :skip, &1})

    {to_send, prepared, statements} = prepare_pkts(pkts, statements, storage, [], [])

    requests =
      Enum.map(plain_tags, &client_request/1) ++
        close_requests ++ write_requests(tags, prepared, [])

    {backend, fake_responses} =
      backend
      |> backend(parked_write: nil, statements: statements)
      |> add_requests(requests)
      |> pop_unanswered()

    {backend, [plain_pkts, close_pkts | to_send], fake_responses, length(evicted)}
  end

  @doc """
  Records a query Supavisor is about to send for itself.
  """
  @spec query(t(), iodata()) :: t()
  def query(backend, msgs),
    do: add_requests(backend, internal_requests(IO.iodata_to_binary(msgs), []))

  @doc """
  Follows the backend through its messages.

  Returns what to forward to the client, and whether the backend became idle, outside a
  transaction, with every request answered and no write parked.
  """
  @spec recv(t(), binary()) :: {t(), iodata(), boolean()}
  def recv(backend(buffer: buffer) = backend, data) do
    {backend, out, synced?} =
      parse_input(backend(backend, buffer: <<>>), buffer <> data, [], false)

    {backend, Enum.reverse(out), synced?}
  end

  @doc """
  Returns whether the backend is idle, outside a transaction, with every request answered and
  no write parked.
  """
  @spec synced?(t()) :: boolean()
  def synced?(backend(state: state, parked_write: parked_write, client_in_copy: client_in_copy)),
    do: state == :idle and parked_write == nil and not client_in_copy

  ## Client writes

  defp prepare_pkts([pkt | pkts], statements, storage, to_send, prepared) when is_binary(pkt),
    do: prepare_pkts(pkts, statements, storage, [pkt | to_send], prepared)

  defp prepare_pkts([pkt | pkts], statements, storage, to_send, prepared) do
    {tag, pkt_to_send, requests, statements} = prepare_pkt(pkt, statements, storage)
    prepared = [{tag, requests} | prepared]
    prepare_pkts(pkts, statements, storage, [pkt_to_send | to_send], prepared)
  end

  defp prepare_pkts([], statements, _storage, to_send, prepared),
    do: {Enum.reverse(to_send), Enum.reverse(prepared), statements}

  defp prepare_pkt({:bind_pkt, name, pkt, parse_pkt}, statements, storage),
    do: prepare_statement_use(?B, name, pkt, parse_pkt, statements, storage)

  defp prepare_pkt({:describe_pkt, name, pkt, parse_pkt}, statements, storage),
    do: prepare_statement_use(?D, name, pkt, parse_pkt, statements, storage)

  defp prepare_pkt({:parse_pkt, name, pkt}, statements, storage) do
    if storage.member?(statements, name),
      do: {?P, [], [{:parse, :fake, name}], storage.touch(statements, name)},
      else: {?P, pkt, [{:parse, :forward, name}], storage.put(statements, name)}
  end

  defp prepare_pkt({:close_pkt, name, pkt}, statements, storage) do
    if storage.member?(statements, name),
      do: {?C, pkt, [{:close, :forward, name}], storage.delete(statements, name)},
      else: {?C, [], [{:close, :fake, name}], statements}
  end

  # A Bind or Describe for a statement the backend doesn't have sends its Parse first.
  defp prepare_statement_use(tag, name, pkt, parse_pkt, statements, storage) do
    request = {message(tag), :forward, name}

    if storage.member?(statements, name) do
      {tag, pkt, [request], storage.touch(statements, name)}
    else
      requests = [{:parse, :skip, name}, request]
      {tag, [parse_pkt, pkt], requests, storage.put(statements, name)}
    end
  end

  defp write_requests([{:ps, tag} | tags], [{tag, requests} | prepared], acc),
    do: write_requests(tags, prepared, Enum.reverse(requests, acc))

  defp write_requests([tag | tags], prepared, acc) when is_integer(tag),
    do: write_requests(tags, prepared, [client_request(tag) | acc])

  defp write_requests([], [], acc), do: Enum.reverse(acc)

  # The backend ignores the CopyDone or CopyFail that ends a COPY that already failed.
  defp drop_copy_end(backend(client_in_copy: true) = backend, tags) do
    case Enum.split_while(tags, &(&1 not in [?c, ?f])) do
      {before, [_copy_end | rest]} -> {backend(backend, client_in_copy: false), before ++ rest}
      {_, []} -> {backend, tags}
    end
  end

  defp drop_copy_end(backend, tags), do: {backend, tags}

  defp client_request(tag), do: {message(tag), :forward, nil}

  defp internal_requests(<<tag, len::32, _::binary-size(len - 4), rest::binary>>, acc),
    do: internal_requests(rest, [{message(tag), :internal, nil} | acc])

  defp internal_requests(<<>>, acc), do: Enum.reverse(acc)

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
  defp message(tag), do: raise("untracked message #{<<tag>>}")

  ## Backend messages

  defp parse_input(backend(streaming: {bytes_left, forward?}) = backend, data, out, synced?) do
    case data do
      <<part::binary-size(bytes_left), rest::binary>> ->
        out = maybe_forward(out, part, forward?)
        parse_input(backend(backend, streaming: nil), rest, out, synced?)

      part ->
        streaming = {bytes_left - byte_size(part), forward?}
        {backend(backend, streaming: streaming), maybe_forward(out, part, forward?), synced?}
    end
  end

  defp parse_input(
         backend,
         <<type, len::32, body::binary-size(len - 4), rest::binary>> = data,
         out,
         synced?
       )
       when type in @tracked_messages do
    out = maybe_forward(out, binary_part(data, 0, len + 1), forward?(backend, type))
    {backend, fake_responses} = backend |> handle_message(type, body) |> pop_unanswered()
    out = Enum.reverse(fake_responses, out)
    parse_input(backend, rest, out, synced? or (type == @ready_for_query and synced?(backend)))
  end

  # A message that doesn't move the backend along is streamed through without waiting for the
  # whole message.
  defp parse_input(backend, <<type, len::32, _::binary>> = data, out, synced?)
       when type not in @tracked_messages do
    streaming = {len + 1, forward?(backend, type)}
    parse_input(backend(backend, streaming: streaming), data, out, synced?)
  end

  defp parse_input(backend, <<>>, out, synced?), do: {backend, out, synced?}

  defp parse_input(backend, partial, out, synced?),
    do: {backend(backend, buffer: partial), out, synced?}

  defp maybe_forward(out, part, true), do: [part | out]
  defp maybe_forward(out, _part, false), do: out

  # Where a message goes depends on the request it answers, the one at the head.
  defp forward?(backend(state: state) = backend, type) do
    case head_request(backend) do
      {_, :internal, _} -> false
      {:parse, :skip, _} when type == @parse_complete and is_answering(state) -> false
      {:close, :skip, _} when type == @close_complete and is_answering(state) -> false
      _ -> true
    end
  end

  defp handle_message(backend, type, body) do
    backend = if type == @error_response, do: record_fatal_error(backend, body), else: backend

    case backend(backend, :state) do
      state when is_answering(state) -> answering(backend, type, body)
      :ignore_till_sync -> ignoring_till_sync(backend, type, body)
      {:copy_in, mode} -> copy_in(backend, mode, type, body)
    end
  end

  defp record_fatal_error(backend, body) do
    error = Server.decode_error_response(body)
    if error["S"] in ["FATAL", "PANIC"], do: backend(backend, fatal_error: error), else: backend
  end

  # A response completes the request at the head if that's the request it answers.
  defp answering(backend, @parse_complete, _body), do: pop_request(backend, :parse)
  defp answering(backend, @bind_complete, _body), do: pop_request(backend, :bind)
  defp answering(backend, @close_complete, _body), do: pop_request(backend, :close)

  defp answering(backend, type, _body) when type in [@row_description, @no_data],
    do: pop_request(backend, :describe)

  defp answering(backend, type, _body)
       when type in [@command_complete, @empty_query_response, @portal_suspended],
       do: pop_request(backend, :execute)

  defp answering(backend, @copy_in_response, _body) do
    case head_request(backend) do
      {:execute, _, _} -> backend(pop_request(backend), state: {:copy_in, :extended})
      {:query, _, _} -> backend(pop_request(backend), state: {:copy_in, :simple})
      _ -> backend
    end
  end

  defp answering(backend, @ready_for_query, <<status>>) do
    case head_request(backend) do
      nil ->
        ready_for_query(backend, status)

      {message, _, _} when message in [:sync, :query, :function_call] ->
        backend |> pop_request() |> ready_for_query(status)

      _ ->
        backend
    end
  end

  defp answering(backend, @error_response, body) do
    case head_request(backend) do
      {message, _, _} = request when message in @extended_query_messages ->
        code = Server.decode_error_response(body)["C"]
        backend = backend |> discard_request() |> reconcile_statement(request, code)
        backend(backend, state: :ignore_till_sync)

      _ ->
        backend
    end
  end

  defp ignoring_till_sync(backend, @ready_for_query, <<status>>),
    do: backend |> pop_requests_through(:sync) |> ready_for_query(status)

  defp ignoring_till_sync(backend, _type, _body), do: backend

  defp copy_in(backend, mode, @command_complete, _body),
    do: backend |> pop_requests_through(:copy_done) |> leave_copy_in(mode)

  defp copy_in(backend, :extended, @error_response, _body),
    do: backend(discard_copy_in_requests(backend), state: :ignore_till_sync)

  defp copy_in(backend, :simple, @error_response, _body),
    do: backend |> discard_copy_in_requests() |> leave_copy_in(:simple)

  defp copy_in(backend, _mode, _type, _body), do: backend

  defp ready_for_query(backend(requests: requests) = backend, status) do
    state =
      cond do
        not :queue.is_empty(requests) -> :busy
        status == ?I -> :idle
        true -> :in_transaction
      end

    backend(backend, state: state)
  end

  # A simple Query still owes its ReadyForQuery once the COPY is over.
  defp leave_copy_in(backend(requests: requests) = backend, :simple),
    do: backend(backend, state: :busy, requests: :queue.in_r({:query, :forward, nil}, requests))

  defp leave_copy_in(backend, :extended), do: backend(backend, state: :busy)

  # The Syncs sent during copy-in were ignored, and so is the CopyDone or CopyFail after them.
  # The client may not have sent that yet.
  defp discard_copy_in_requests(backend) do
    case head_request(backend) do
      {:sync, _, _} -> backend |> discard_request() |> discard_copy_in_requests()
      {message, _, _} when message in [:copy_done, :copy_fail] -> discard_request(backend)
      nil -> backend(backend, client_in_copy: true)
      _ -> backend
    end
  end

  ## Requests

  defp add_requests(backend, []), do: backend

  defp add_requests(backend(state: state, requests: requests) = backend, new_requests) do
    state = if is_answering(state), do: :busy, else: state
    requests = :queue.join(requests, :queue.from_list(new_requests))
    backend(backend, state: state, requests: requests)
  end

  defp head_request(backend(requests: requests)) do
    case :queue.peek(requests) do
      {:value, request} -> request
      :empty -> nil
    end
  end

  defp pop_request(backend(requests: requests) = backend),
    do: backend(backend, requests: :queue.drop(requests))

  defp pop_request(backend, message) do
    case head_request(backend) do
      {^message, _, _} -> pop_request(backend)
      _ -> backend
    end
  end

  # The backend answered the first `message`, and ignored every request before it.
  defp pop_requests_through(backend, message) do
    case head_request(backend) do
      {^message, _, _} -> pop_request(backend)
      nil -> backend
      _ -> backend |> discard_request() |> pop_requests_through(message)
    end
  end

  # The backend ignores a CopyDone or CopyFail outside a COPY, and a Parse or Close that wasn't
  # sent is answered as soon as it's next. Its response belongs to a new extended protocol
  # batch, still waiting for its Sync.
  defp pop_unanswered(backend(state: state, requests: requests) = backend)
       when is_answering(state),
       do: pop_unanswered(backend, requests, [])

  defp pop_unanswered(backend), do: {backend, []}

  defp pop_unanswered(backend, requests, fake_responses) do
    case :queue.peek(requests) do
      {:value, {message, _, _}} when message in [:copy_done, :copy_fail] ->
        pop_unanswered(backend, :queue.drop(requests), fake_responses)

      {:value, {:parse, :fake, _}} ->
        fake_responses = [Server.parse_complete_message() | fake_responses]
        pop_unanswered(backend(backend, state: :busy), :queue.drop(requests), fake_responses)

      {:value, {:close, :fake, _}} ->
        fake_responses = [Server.close_complete_message() | fake_responses]
        pop_unanswered(backend(backend, state: :busy), :queue.drop(requests), fake_responses)

      _ ->
        {backend(backend, requests: requests), Enum.reverse(fake_responses)}
    end
  end

  # The backend didn't carry out the request at the head, so its effect on the statements is
  # undone.
  defp discard_request(
         backend(requests: requests, storage: storage, statements: statements) = backend
       ) do
    {{:value, request}, requests} = :queue.out(requests)

    statements =
      case request do
        {:parse, action, name} when action in [:forward, :skip] and is_binary(name) ->
          storage.delete(statements, name)

        {:close, action, name} when action in [:forward, :skip] and is_binary(name) ->
          storage.put(statements, name)

        _ ->
          statements
      end

    backend(backend, requests: requests, statements: statements)
  end

  defp reconcile_statement(
         backend(storage: storage, statements: statements) = backend,
         {:parse, _, name},
         @duplicate_pstatement
       )
       when is_binary(name),
       do: backend(backend, statements: storage.put(statements, name))

  defp reconcile_statement(
         backend(storage: storage, statements: statements) = backend,
         {message, _, name},
         @undefined_pstatement
       )
       when message in [:bind, :describe] and is_binary(name),
       do: backend(backend, statements: storage.delete(statements, name))

  defp reconcile_statement(backend, _request, _code), do: backend
end
