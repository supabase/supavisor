defmodule Supavisor.Protocol.PreparedStatements do
  @moduledoc """
  Handles prepared statement binary packet transformations.
  """

  alias Supavisor.Protocol.PreparedStatements.PreparedStatement

  @type statement_map() :: %{String.t() => PreparedStatement.t()}

  @type statement_name() :: String.t()

  @type pkt() :: binary()

  @type handled_pkt() ::
          {:parse_pkt, statement_name(), pkt()}
          | {:bind_pkt, statement_name(), bind_pkt :: pkt(), parse_pkt :: pkt()}
          | {:close_pkt, statement_name(), pkt()}
          | pkt()

  @client_limit 100
  @backend_limit 200

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
  @spec handle_pkt(statement_map(), pkt()) ::
          {:ok, statement_map(), handled_pkt()}
          | {:error, :max_prepared_statements}
          | {:error, :prepared_statement_on_simple_query}
  def handle_pkt(client_statements, binary) do
    case binary do
      # Parse message (P)
      <<?P, len::32, rest::binary>> ->
        handle_parse_message(client_statements, binary, len, rest)

      # Bind message (B)
      <<?B, len::32, rest::binary>> ->
        handle_bind_message(client_statements, len, rest)

      # Close message (C)
      <<?C, len::32, ?S, rest::binary>> ->
        handle_close_message(client_statements, len, rest)

      # Describe message (D)
      <<?D, len::32, ?S, rest::binary>> ->
        handle_describe_message(client_statements, len, rest)

      # Query message (Q)
      <<?Q, len::32, rest::binary>> ->
        handle_simple_query_message(client_statements, binary, len, rest)

      # All other messages pass through unchanged
      _ ->
        {:ok, client_statements, binary}
    end
  end

  defp handle_parse_message(client_statements, original_bin, len, rest) do
    case extract_null_terminated_string(rest) do
      # Unnamed prepared statement - pass through unchanged
      {"", _} ->
        {:ok, client_statements, original_bin}

      # Named prepared statement - generate server-side name
      {client_side_name, remaining} ->
        if map_size(client_statements) >= @client_limit do
          {:error, :max_prepared_statements}
        else
          server_side_name = "supavisor_#{System.unique_integer()}"

          new_len = len + (byte_size(server_side_name) - byte_size(client_side_name))
          new_bin = <<?P, new_len::32, server_side_name::binary, 0, remaining::binary>>

          prepared_statement = %PreparedStatement{
            name: server_side_name,
            parse_pkt: new_bin
          }

          new_client_statements = Map.put(client_statements, client_side_name, prepared_statement)
          {:ok, new_client_statements, {:parse_pkt, server_side_name, new_bin}}
        end
    end
  end

  defp handle_bind_message(client_statements, len, rest) do
    {_portal_name, after_portal} = extract_null_terminated_string(rest)
    {client_side_name, packet_after_client_name} = extract_null_terminated_string(after_portal)

    case Map.get(client_statements, client_side_name) do
      %PreparedStatement{name: server_side_name, parse_pkt: parse_pkt} ->
        new_len = len + (byte_size(server_side_name) - byte_size(client_side_name))

        new_bin =
          <<?B, new_len::32, 0, server_side_name::binary, 0, packet_after_client_name::binary>>

        {:ok, client_statements, {:bind_pkt, server_side_name, new_bin, parse_pkt}}

      nil ->
        # Unknown statement name - use empty string
        # This probably should be an error. Need to double check it.
        new_len = len + (0 - byte_size(client_side_name))
        new_bin = <<?B, new_len::32, 0, 0, packet_after_client_name::binary>>
        {:ok, client_statements, {:bind_pkt, "", new_bin, nil}}
    end
  end

  defp handle_close_message(client_statements, len, rest) do
    {client_side_name, _} = extract_null_terminated_string(rest)

    {prepared_statement, new_client_statements} = Map.pop(client_statements, client_side_name)

    server_side_name =
      case prepared_statement do
        %PreparedStatement{name: name} -> name
        nil -> "supavisor_none"
      end

    new_len = len + (byte_size(server_side_name) - byte_size(client_side_name))
    new_bin = <<?C, new_len::32, ?S, server_side_name::binary, 0>>

    {:ok, new_client_statements, {:close_pkt, server_side_name, new_bin}}
  end

  defp handle_describe_message(client_statements, len, rest) do
    {client_side_name, _} = extract_null_terminated_string(rest)

    server_side_name =
      case Map.get(client_statements, client_side_name) do
        %PreparedStatement{name: name} -> name
        nil -> ""
      end

    new_len = len + (byte_size(server_side_name) - byte_size(client_side_name))
    new_bin = <<?D, new_len::32, ?S, server_side_name::binary, 0>>

    {:ok, client_statements, {:describe_pkt, server_side_name, new_bin}}
  end

  defp handle_simple_query_message(client_statements, binary, _len, rest) do
    case rest do
      "PREPARE" <> _ ->
        IO.inspect(String.trim(rest, <<0>>), label: :r)
        {:error, :prepared_statement_on_simple_query}

      _ ->
        {:ok, client_statements, binary}
    end
  end

  defp extract_null_terminated_string(binary) do
    case :binary.split(binary, <<0>>) do
      [string, rest] -> {string, rest}
      [string] -> {string, <<>>}
    end
  end
end
