defmodule Supavisor.Protocol.PreparedStatements.PreparedStatementTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.PreparedStatement

  setup do
    client_statements = %{}

    {:ok, client_statements: client_statements}
  end

  describe "handle_pkt/2" do
    test "unnamed prepared statements are passed through unchanged", %{
      client_statements: client_statements
    } do
      original_bin = <<?P, 16::32, 0, 115, 101, 108, 101, 99, 116, 32, 49, 0, 0, 0>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should return unchanged
      assert new_client_statements == client_statements
      assert result == original_bin
    end

    test "close message updates statement name and binary" do
      parse_pkt =
        <<?P, 25::32, 115, 101, 114, 118, 101, 114, 95, 115, 116, 109, 116, 0, 115, 101, 108, 101,
          99, 116, 32, 49, 0, 0, 0>>

      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = %{"test_stmt" => prepared_statement}

      # Close message for prepared statement
      original_bin = <<?C, 15::32, ?S, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should remove from client_statements
      assert new_client_statements == %{}

      # Should return close_pkt tuple with statement name
      assert {:close_pkt, "server_stmt", result_bin} = result

      # Verify the result binary has the correct format
      assert <<?C, _len::32, ?S, "server_stmt", 0>> = result_bin
    end

    test "parse message generates new server-side name", %{
      client_statements: client_statements
    } do
      # Parse message with named statement
      original_bin =
        <<?P, 25::32, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0, 115, 101, 108, 101, 99, 116,
          32, 49, 0, 0, 0>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should add mapping to client_statements
      assert map_size(new_client_statements) == 1
      assert Map.has_key?(new_client_statements, "test_stmt")

      prepared_statement = Map.get(new_client_statements, "test_stmt")
      assert %PreparedStatement{} = prepared_statement
      assert String.starts_with?(prepared_statement.name, "supavisor_")

      # Should return parse_pkt tuple with statement name
      assert {:parse_pkt, server_name, result_bin} = result
      assert server_name == prepared_statement.name

      # Verify the result binary has the correct format
      assert <<?P, _len::32, ^server_name::binary-size(byte_size(prepared_statement.name)), 0,
               "select 1", 0, 0, 0>> = result_bin

      assert prepared_statement.parse_pkt == result_bin
    end

    test "bind message updates statement name" do
      parse_pkt =
        <<?P, 25::32, 115, 101, 114, 118, 101, 114, 95, 115, 116, 109, 116, 0, 115, 101, 108, 101,
          99, 116, 32, 49, 0, 0, 0>>

      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = %{"test_stmt" => prepared_statement}

      # Bind message referencing prepared statement
      original_bin =
        <<?B, 21::32, 0, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0, 0, 0, 0, 0, 0, 0>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should return bind_pkt tuple with statement name
      assert {:bind_pkt, "server_stmt", result_bin, returned_parse_pkt} = result
      assert returned_parse_pkt == parse_pkt

      # Verify the result binary has the correct format
      assert <<?B, _len::32, 0, "server_stmt", 0, 0, 0, 0, 0, 0, 0>> = result_bin
    end

    test "describe message updates statement name" do
      parse_pkt =
        <<?P, 25::32, 115, 101, 114, 118, 101, 114, 95, 115, 116, 109, 116, 0, 115, 101, 108, 101,
          99, 116, 32, 49, 0, 0, 0>>

      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = %{"test_stmt" => prepared_statement}

      # Describe message for prepared statement
      original_bin = <<?D, 15::32, ?S, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should return describe_pkt tuple with statement name
      assert {:describe_pkt, "server_stmt", result_bin} = result

      # Verify the result binary has the correct format
      assert <<?D, _len::32, ?S, "server_stmt", 0>> = result_bin
    end

    test "passthrough for message types we ignore", %{
      client_statements: client_statements
    } do
      # Execute message (should pass through)
      original_bin = <<?E, 9::32, 0, 0, 0, 0, 200>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should return unchanged
      assert new_client_statements == client_statements
      assert result == original_bin
    end

    test "bind message with unknown statement name" do
      client_statements = %{}

      # Bind message referencing unknown statement
      original_bin =
        <<?B, 21::32, 0, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0, 0, 0, 0, 0, 0, 0>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should return bind_pkt tuple with empty statement name and nil parse_pkt
      assert {:bind_pkt, "", result_bin, nil} = result

      # Verify the result binary has the correct format (empty statement name)
      assert <<?B, _len::32, 0, 0, 0, 0, 0, 0, 0, 0>> = result_bin
    end

    test "describe message with unknown statement name" do
      client_statements = %{}

      # Describe message for unknown statement
      original_bin = <<?D, 15::32, ?S, 116, 101, 115, 116, 95, 115, 116, 109, 116, 0>>

      {new_client_statements, result} =
        PreparedStatements.handle_pkt(client_statements, original_bin)

      # Should not change client_statements
      assert new_client_statements == client_statements

      # Should return describe_pkt tuple with empty statement name
      assert {:describe_pkt, "", result_bin} = result

      # Verify the result binary has the correct format (empty statement name)
      assert <<?D, _len::32, ?S, 0>> = result_bin
    end
  end
end
