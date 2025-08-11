defmodule Supavisor.Protocol.PreparedStatements do
  @moduledoc """
  Handles prepared statement binary packet transformations.
  """

  @behaviour Supavisor.Protocol.MessageHandler

  alias Supavisor.Protocol.PreparedStatements.PreparedStatement
  alias Supavisor.Protocol.PreparedStatements.Storage

  @type statement_name() :: String.t()
  @type pkt() :: binary()

  @type handled_pkt() ::
          {:parse_pkt, statement_name(), pkt()}
          | {:bind_pkt, statement_name(), bind_pkt :: pkt(), parse_pkt :: pkt()}
          | {:close_pkt, statement_name(), pkt()}
          | {:describe_pkt, statement_name(), pkt()}
          | pkt()

  @client_limit 100
  @backend_limit 200
  @client_memory_limit_bytes 1_000_000

  @impl true
  def handled_message_types, do: [?P, ?B, ?C, ?D, ?Q]

  @impl true
  def init_state, do: Storage.new()

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

  @impl true
  def handle_message(client_statements, tag, len, payload) do
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
    <<type, rest::binary>> = payload
    {name, _} = extract_null_terminated_string(rest)

    case type do
      ?S ->
        # Close statement - apply prepared statement name translation
        {prepared_statement, new_client_statements} = Storage.pop(client_statements, name)

        server_side_name =
          case prepared_statement do
            %PreparedStatement{name: server_name} -> server_name
            nil -> "supavisor_none"
          end

        new_len = len + (byte_size(server_side_name) - byte_size(name))
        new_bin = <<?C, new_len::32, ?S, server_side_name::binary, 0>>
        {:ok, new_client_statements, {:close_pkt, server_side_name, new_bin}}

      _ ->
        {:ok, client_statements, <<?C, len::32, payload::binary>>}
    end
  end

  defp handle_describe_message(client_statements, len, payload) do
    <<type, rest::binary>> = payload
    {name, _} = extract_null_terminated_string(rest)

    case type do
      ?S ->
        # Describe statement - apply prepared statement name translation
        case name do
          # Unnamed prepared statements are passed through unchanged
          "" ->
            {:ok, client_statements, <<?D, len::32, payload::binary>>}

          _ ->
            case Storage.get(client_statements, name) do
              %PreparedStatement{name: server_name} ->
                new_len = len + (byte_size(server_name) - byte_size(name))
                new_bin = <<?D, new_len::32, ?S, server_name::binary, 0>>
                {:ok, client_statements, {:describe_pkt, server_name, new_bin}}

              nil ->
                {:error, :prepared_statement_not_found, name}
            end
        end

      _ ->
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
