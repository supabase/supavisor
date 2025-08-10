defmodule Supavisor.Protocol.PreparedStatements do
  @moduledoc """
  Handles prepared statement binary packet transformations.
  """

  alias Supavisor.Protocol.PreparedStatements.PreparedStatement
  alias Supavisor.Protocol.PreparedStatements.Storage

  require Record

  Record.defrecord(
    :parse_state,
    prepared_statements: Storage.new(),
    pending_bin: <<>>,
    pkts: [],
    in_flight_pkt: nil
  )

  @type parse_state() ::
          record(:parse_state,
            prepared_statements: Storage.t(),
            pending_bin: binary(),
            pkts: [handled_pkt()],
            in_flight_pkt: {tag :: binary(), remaining_len :: non_neg_integer()} | nil
          )

  @type statement_name() :: String.t()

  @type pkt() :: binary()

  @type handled_pkt() ::
          {:parse_pkt, statement_name(), pkt()}
          | {:bind_pkt, statement_name(), bind_pkt :: pkt(), parse_pkt :: pkt()}
          | {:close_pkt, statement_name(), pkt()}
          | pkt()

  @client_limit 100
  @backend_limit 200
  @client_memory_limit_bytes 1_000_000

  def new_parse_state() do
    parse_state(
      prepared_statements: Storage.new(),
      pending_bin: <<>>,
      pkts: [],
      in_flight_pkt: nil
    )
  end

  @doc """
  Upper limit of prepared statements from the client
  """
  @spec client_limit() :: pos_integer()
  def client_limit, do: @client_limit

  @doc """
  Upper limit of prepared statements backend-side.

  Should rotate prepared statements to avoid surpassing it.
  """
  @spec backend_limit() :: pos_integer()
  def backend_limit, do: @backend_limit

  @doc """
  Upper limit of prepared statements memory from the client in bytes
  """
  @spec client_memory_limit_bytes() :: pos_integer()
  def client_memory_limit_bytes, do: @client_memory_limit_bytes

  @doc """
  Receives a statement name and returns a close packet for it
  """
  @spec build_close_pkt(statement_name) :: pkt()
  def build_close_pkt(statement_name) do
    len = byte_size(statement_name)
    <<?C, len + 6::32, ?S, statement_name::binary, 0>>
  end

  @doc """
  Handles prepared statement packets and returns appropriate tuples for packets
  that need special treatment according to the protocol.
  """
  @spec handle_pkts(parse_state(), pkt()) ::
          {:ok, parse_state(), [handled_pkt()]}
          | {:error, :max_prepared_statements}
          | {:error, :max_prepared_statements_memory}
          | {:error, :prepared_statement_on_simple_query}
          | {:error, :duplicate_prepared_statement, statement_name()}
          | {:error, :prepared_statement_not_found, statement_name()}
  def handle_pkts(acc, binary) do
    case do_handle_pkts(acc, binary) do
      {:ok, acc} ->
        {:ok, parse_state(acc, pkts: []), Enum.reverse(parse_state(acc, :pkts))}

      error ->
        error
    end
  end

  defp do_handle_pkts(acc, binary) do
    case acc do
      parse_state(in_flight_pkt: {_tag, _len}) ->
        handle_in_flight(acc, binary)

      parse_state(pending_bin: "") ->
        handle_pkt(acc, binary)

      parse_state(pending_bin: pending_bin) ->
        handle_pkt(parse_state(acc, pending_bin: ""), pending_bin <> binary)
    end
  end

  defp handle_in_flight(acc, binary) do
    {tag, remaining_len} = parse_state(acc, :in_flight_pkt)

    case binary do
      # Message is complete
      <<rest_of_message::binary-size(remaining_len), rest::binary>> ->
        new_parse_state =
          parse_state(acc,
            pkts: [rest_of_message | parse_state(acc, :pkts)],
            in_flight_pkt: nil
          )

        do_handle_pkts(new_parse_state, rest)

      # Message is incomplete, continue in flight
      rest_of_message ->
        new_parse_state =
          parse_state(acc,
            pkts: [rest_of_message | parse_state(acc, :pkts)],
            in_flight_pkt: {tag, remaining_len - byte_size(rest_of_message)}
          )

        {:ok, new_parse_state}
    end
  end

  defp handle_pkt(acc, binary) do
    case binary do
      <<tag, len::32, payload::binary-size(len - 4), rest::binary>> ->
        case handle_message(acc, tag, len, payload) do
          {:ok, client_statements, pkt} ->
            do_handle_pkts(
              parse_state(acc,
                pkts: [pkt | parse_state(acc, :pkts)],
                prepared_statements: client_statements
              ),
              rest
            )

          err ->
            err
        end

      # Incomplete message with known len
      <<tag, len::32, _rest::binary>> = bin ->
        # If we are interested in the content, we store it in pending so we can handle it later
        if tag in [?P, ?B, ?C, ?D, ?Q] do
          {:ok, parse_state(acc, pending_bin: bin)}
        else
          # IO.inspect(bin, label: :got_this)
          {:ok,
           parse_state(acc,
             pkts: [bin | parse_state(acc, :pkts)],
             in_flight_pkt: {tag, len + 1 - byte_size(bin)}
           )}
        end

      # Incomplete message
      bin ->
        {:ok, parse_state(acc, pending_bin: bin)}
    end
  end

  defp handle_message(acc, tag, len, payload) do
    client_statements = parse_state(acc, :prepared_statements)

    case tag do
      ?P -> handle_parse_message(client_statements, len, payload)
      ?B -> handle_bind_message(client_statements, len, payload)
      ?C -> handle_close_message(client_statements, len, payload)
      ?D -> handle_describe_message(client_statements, len, payload)
      ?Q -> handle_simple_query_message(client_statements, len, payload)
      _ -> {:ok, client_statements, <<tag, len::32, payload::binary>>}
    end
  end

  defp handle_parse_message(client_statements, len, payload) do
    case extract_null_terminated_string(payload) do
      # Unnamed prepared statements are passed through unchanged
      {"", _} ->
        {:ok, client_statements, <<?P, len::32, payload::binary>>}

      {client_side_name, remaining} ->
        cond do
          Storage.statement_count(client_statements) >= @client_limit ->
            {:error, :max_prepared_statements}

          Storage.statement_memory(client_statements) > @client_memory_limit_bytes ->
            {:error, :max_prepared_statements_memory}

          Storage.get(client_statements, client_side_name) ->
            {:error, :duplicate_prepared_statement, client_side_name}

          true ->
            server_side_name = gen_server_side_name(payload)

            new_len = len + (byte_size(server_side_name) - byte_size(client_side_name))
            new_bin = <<?P, new_len::32, server_side_name::binary, 0, remaining::binary>>

            prepared_statement = %PreparedStatement{
              name: server_side_name,
              parse_pkt: new_bin
            }

            new_client_statements =
              Storage.put(client_statements, client_side_name, prepared_statement)

            {:ok, new_client_statements, {:parse_pkt, server_side_name, new_bin}}
        end
    end
  end

  defp handle_bind_message(client_statements, len, payload) do
    {_portal_name, after_portal} = extract_null_terminated_string(payload)

    case extract_null_terminated_string(after_portal) do
      {"", _} ->
        {:ok, client_statements, <<?B, len::32, payload::binary>>}

      {client_side_name, packet_after_client_name} ->
        case Storage.get(client_statements, client_side_name) do
          %PreparedStatement{name: server_side_name, parse_pkt: parse_pkt} ->
            new_len = len + (byte_size(server_side_name) - byte_size(client_side_name))

            new_bin =
              <<?B, new_len::32, 0, server_side_name::binary, 0,
                packet_after_client_name::binary>>

            {:ok, client_statements, {:bind_pkt, server_side_name, new_bin, parse_pkt}}

          nil ->
            {:error, :prepared_statement_not_found}
        end
    end
  end

  defp handle_close_message(client_statements, len, payload) do
    # Skip the statement type byte (?S) at the beginning of payload
    <<_type, rest::binary>> = payload
    {client_side_name, _} = extract_null_terminated_string(rest)

    {prepared_statement, new_client_statements} = Storage.pop(client_statements, client_side_name)

    server_side_name =
      case prepared_statement do
        %PreparedStatement{name: name} -> name
        nil -> "supavisor_none"
      end

    new_len = len + (byte_size(server_side_name) - byte_size(client_side_name))
    new_bin = <<?C, new_len::32, ?S, server_side_name::binary, 0>>

    {:ok, new_client_statements, {:close_pkt, server_side_name, new_bin}}
  end

  defp handle_describe_message(client_statements, len, payload) do
    <<type, rest::binary>> = payload
    {name, _} = extract_null_terminated_string(rest)

    case type do
      ?S ->
        # Describe statement - apply prepared statement name translation
        server_side_name =
          case Storage.get(client_statements, name) do
            %PreparedStatement{name: server_name} -> server_name
            nil -> name
          end

        new_len = len + (byte_size(server_side_name) - byte_size(name))
        new_bin = <<?D, new_len::32, ?S, server_side_name::binary, 0>>
        {:ok, client_statements, {:describe_pkt, server_side_name, new_bin}}

      ?P ->
        # Describe portal - pass through unchanged
        {:ok, client_statements, <<?D, len::32, payload::binary>>}

      _ ->
        # Unknown type - pass through unchanged
        {:ok, client_statements, <<?D, len::32, payload::binary>>}
    end
  end

  defp handle_simple_query_message(client_statements, len, payload) do
    case payload do
      "PREPARE" <> _ ->
        {:error, :prepared_statement_on_simple_query}

      _ ->
        {:ok, client_statements, <<?Q, len::32, payload::binary>>}
    end
  end

  defp extract_null_terminated_string(binary) do
    case :binary.split(binary, <<0>>) do
      [string, rest] -> {string, rest}
      [string] -> {string, <<>>}
    end
  end

  defp gen_server_side_name(binary) do
    hash =
      :crypto.hash(:sha256, binary)
      |> Base.encode64(padding: false)

    "sv_#{hash}"
  end
end
