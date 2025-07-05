defmodule Supavisor.Protocol.PreparedStatementsTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.PreparedStatement
  alias Supavisor.Protocol.Client

  setup do
    client_statements = %{}

    {:ok, client_statements: client_statements}
  end

  describe "handle_pkt/2" do
    test "unnamed prepared statements are passed through unchanged", %{
      client_statements: client_statements
    } do
      original_bin = <<80, 0, 0, 0, 16, 0, 115, 101, 108, 101, 99, 116, 32, 49, 0, 0, 0>>
      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should return unchanged
      assert new_client_statements == client_statements
      assert result_pkt == pkt
      assert result_pkt.bin == original_bin
      assert result_pkt.payload.str_name == ""
    end

    test "close message updates statement name and binary" do
      parse_pkt = %{tag: :parse_message, payload: %{str_name: "server_stmt"}}
      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = %{"test_stmt" => prepared_statement}

      # Close message for prepared statement
      original_bin = <<67, 0, 0, 0, 15, 83, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0>>
      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should remove from client_statements
      assert new_client_statements == %{}

      # Should update the packet
      assert result_pkt.tag == :close_message
      assert result_pkt.payload.str_name == "server_stmt"
      assert result_pkt.payload.char == "S"

      # Verify binary can be decoded
      {:ok, [decoded_pkt], _} = Client.decode(result_pkt.bin)
      assert decoded_pkt == result_pkt
    end

    test "parse message generates new server-side name", %{
      client_statements: client_statements
    } do
      # Parse message with named statement
      original_bin =
        <<80, 0, 0, 0, 25, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0, 115, 101, 108, 101, 99,
          116, 32, 49, 0, 0, 0>>

      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should add mapping to client_statements
      assert map_size(new_client_statements) == 1
      assert Map.has_key?(new_client_statements, "test_stmt")

      prepared_statement = Map.get(new_client_statements, "test_stmt")
      assert %PreparedStatement{} = prepared_statement
      assert String.starts_with?(prepared_statement.name, "supavisor_")
      assert prepared_statement.parse_pkt == result_pkt

      # Should update the packet
      assert result_pkt.tag == :parse_message
      assert result_pkt.payload.str_name == prepared_statement.name

      # Verify binary can be decoded
      {:ok, [decoded_pkt], _} = Client.decode(result_pkt.bin)
      assert decoded_pkt == result_pkt
    end

    test "bind message updates statement name" do
      parse_pkt = %{tag: :parse_message, payload: %{str_name: "server_stmt"}}
      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = %{"test_stmt" => prepared_statement}

      # Bind message referencing prepared statement
      original_bin =
        <<66, 0, 0, 0, 21, 0, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0, 0, 0, 0, 0, 0, 0>>

      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should update the packet
      assert result_pkt.tag == :bind_message
      assert result_pkt.payload.str_name == "server_stmt"
      assert result_pkt.payload.parse_pkt == parse_pkt

      # Verify binary can be decoded
      {:ok, [decoded_pkt], _} = Client.decode(result_pkt.bin)
      assert decoded_pkt == Map.update!(result_pkt, :payload, &Map.delete(&1, :parse_pkt))
    end

    test "describe message updates statement name" do
      parse_pkt = %{tag: :parse_message, payload: %{str_name: "server_stmt"}}
      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = %{"test_stmt" => prepared_statement}

      # Describe message for prepared statement
      original_bin = <<68, 0, 0, 0, 15, 83, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0>>
      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should update the packet
      assert result_pkt.tag == :describe_message
      assert result_pkt.payload.str_name == "server_stmt"

      # Verify binary can be decoded
      {:ok, [decoded_pkt], _} = Client.decode(result_pkt.bin)
      assert decoded_pkt == result_pkt
    end

    test "passthrough for message types we ignore", %{
      client_statements: client_statements
    } do
      # Execute message (should pass through)
      original_bin = <<69, 0, 0, 0, 9, 0, 0, 0, 0, 200>>
      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should return unchanged
      assert new_client_statements == client_statements
      assert result_pkt == pkt
      assert result_pkt.bin == original_bin

      # Verify binary can be decoded
      {:ok, [decoded_pkt], _} = Client.decode(result_pkt.bin)
      assert decoded_pkt == result_pkt
    end

    test "bind message with unknown statement name" do
      client_statements = %{}

      # Bind message referencing unknown statement
      original_bin =
        <<66, 0, 0, 0, 21, 0, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0, 0, 0, 0, 0, 0, 0>>

      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should update the packet with nil server name
      assert result_pkt.tag == :bind_message
      assert result_pkt.payload.str_name == ""
      assert result_pkt.payload.parse_pkt == nil

      # Verify binary can be decoded
      {:ok, [decoded_pkt], _} = Client.decode(result_pkt.bin)
      assert decoded_pkt == Map.update!(result_pkt, :payload, &Map.delete(&1, :parse_pkt))
    end

    test "describe message with unknown statement name" do
      client_statements = %{}

      # Describe message for unknown statement
      original_bin = <<68, 0, 0, 0, 15, 83, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0>>
      {:ok, [pkt], _} = Client.decode(original_bin)

      {new_client_statements, result_pkt} =
        PreparedStatements.handle_pkt(client_statements, pkt)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should update the packet with nil server name
      assert result_pkt.tag == :describe_message
      assert result_pkt.payload.str_name == ""

      # Verify binary can be decoded
      {:ok, [decoded_pkt], _} = Client.decode(result_pkt.bin)
      assert decoded_pkt == result_pkt
    end
  end
end
