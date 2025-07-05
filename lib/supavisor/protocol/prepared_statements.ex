defmodule Supavisor.Protocol.PreparedStatements do
  @moduledoc """
  This module handles prepared statements through the extended query protocol
  for the client handler
  """

  alias Supavisor.Protocol.Client.Pkt
  alias Supavisor.Protocol.PreparedStatements.PreparedStatement

  # Unnamed prepared statements are sent untouched
  def handle_pkt(
        client_statements,
        %Pkt{payload: %{str_name: ""}} = pkt
      ) do
    {client_statements, pkt}
  end

  def handle_pkt(
        client_statements,
        %Pkt{tag: :close_message, payload: %{char: "S"}} = pkt
      ) do
    client_side_name = pkt.payload.str_name

    # If the prepared statement doesn't exist, no need to clean
    # (some clients send this before preparing any statement)
    {prepared_statement, client_statements} =
      Map.pop(client_statements, client_side_name)

    server_side_name =
      case prepared_statement do
        %PreparedStatement{name: name} -> name
        nil -> "supavisor_none"
      end

    len = new_len(pkt, client_side_name, server_side_name)

    new_bin =
      <<?C, len::32, ?S, server_side_name::binary, 0>>

    updated_payload = %{pkt.payload | str_name: server_side_name}

    updated_pkt = %{
      pkt
      | bin: new_bin,
        len: len + 1,
        payload: updated_payload
    }

    {client_statements, updated_pkt}
  end

  def handle_pkt(client_statements, %Pkt{tag: :parse_message} = pkt) do
    %{str_name: client_side_name} = pkt.payload

    # TODO: if we generate a "per query" key here, we can reduce the number
    # of duplicate prepared statements. We can achieve that with pg_parser, but
    # lets do it as a future improvement
    server_side_name = "supavisor_#{System.unique_integer()}"

    <<_type, _len::32, _statement_name::binary-size(byte_size(client_side_name)), 0,
      query_and_params::binary>> = pkt.bin

    len = new_len(pkt, client_side_name, server_side_name)

    new_bin =
      <<?P, len::32, server_side_name::binary, 0, query_and_params::binary>>

    updated_payload = %{pkt.payload | str_name: server_side_name}

    updated_pkt = %{
      pkt
      | bin: new_bin,
        len: len + 1,
        payload: updated_payload
    }

    prepared_statement = %PreparedStatement{
      name: server_side_name,
      parse_pkt: updated_pkt
    }

    {Map.put(client_statements, client_side_name, prepared_statement), updated_pkt}
  end

  def handle_pkt(
        client_statements,
        %Pkt{tag: :bind_message} = pkt
      ) do
    %{str_name: client_side_name} = pkt.payload
    prepared_statement = Map.get(client_statements, client_side_name)

    <<_type, _len::32, rest::binary>> = pkt.bin
    [_, rest] = :binary.split(rest, <<0>>)
    [_, packet_after_server_side_name] = :binary.split(rest, <<0>>)

    # TODO: should return error to client when the name is not known
    {server_side_name, parse_pkt} =
      case prepared_statement do
        %PreparedStatement{name: name, parse_pkt: parse_pkt} -> {name, parse_pkt}
        nil -> {"", nil}
      end

    len = new_len(pkt, client_side_name, server_side_name)

    new_bin =
      <<
        ?B,
        len::32,
        0,
        server_side_name::binary,
        0,
        packet_after_server_side_name::binary
      >>

    updated_payload =
      pkt.payload
      |> Map.put(:str_name, server_side_name)
      |> Map.put(:parse_pkt, parse_pkt)

    updated_pkt = %{
      pkt
      | bin: new_bin,
        len: len + 1,
        payload: updated_payload
    }

    {client_statements, updated_pkt}
  end

  def handle_pkt(client_statements, %Pkt{tag: :describe_message} = pkt) do
    client_side_name = pkt.payload.str_name
    prepared_statement = Map.get(client_statements, client_side_name)

    server_side_name =
      case prepared_statement do
        %PreparedStatement{name: name} -> name
        nil -> ""
      end

    len = new_len(pkt, client_side_name, server_side_name)

    new_bin =
      <<?D, len::32, ?S, server_side_name::binary, 0>>

    updated_payload = %{pkt.payload | str_name: server_side_name}

    updated_pkt = %{
      pkt
      | bin: new_bin,
        len: len + 1,
        payload: updated_payload
    }

    {client_statements, updated_pkt}
  end

  def handle_pkt(client_statements, pkt) do
    {client_statements, pkt}
  end

  defp new_len(pkt, old_name, new_name) do
    pkt.len + (byte_size(new_name) - byte_size(old_name)) - 1
  end
end
