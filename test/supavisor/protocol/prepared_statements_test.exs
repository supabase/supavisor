defmodule Supavisor.Protocol.PreparedStatements.PreparedStatementTest do
  use ExUnit.Case, async: true

  alias Supavisor.Protocol.MessageStreamer
  alias Supavisor.Protocol.PreparedStatements
  alias Supavisor.Protocol.PreparedStatements.PreparedStatement
  alias Supavisor.Protocol.PreparedStatements.Storage

  require MessageStreamer

  setup do
    stream_state = MessageStreamer.new_stream_state(PreparedStatements)

    {:ok, stream_state: stream_state}
  end

  describe "handle_packets/2" do
    test "unnamed prepared statements are passed through unchanged", %{
      stream_state: stream_state
    } do
      original_bin = <<?P, 16::32, 0, "select 1", 0, 0, 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [original_bin]
    end

    test "close message updates statement name and binary" do
      parse_pkt =
        <<?P, 27::32, "server_stmt", 0, "select 1", 0, 0, 0>>

      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = Storage.put(Storage.new(), "test_stmt", prepared_statement)

      stream_state =
        MessageStreamer.stream_state(
          MessageStreamer.new_stream_state(PreparedStatements),
          handler_state: client_statements
        )

      # Close message for prepared statement
      original_bin = <<?C, 15::32, ?S, "test_stmt", 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should remove from client_statements
      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               Storage.new()

      # Should return close_pkt tuple with statement name
      assert [result_pkt] = result
      assert {:close_pkt, "server_stmt", result_bin} = result_pkt

      # Verify the result binary has the correct format
      assert <<?C, _len::32, ?S, "server_stmt", 0>> = result_bin
    end

    test "parse message generates new server-side name", %{
      stream_state: stream_state
    } do
      # Parse message with named statement
      original_bin =
        <<?P, 25::32, "test_stmt", 0, "select 1", 0, 0, 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should add mapping to client_statements
      new_client_statements =
        MessageStreamer.stream_state(new_stream_state, :handler_state)

      assert Storage.statement_count(new_client_statements) == 1
      prepared_statement = Storage.get(new_client_statements, "test_stmt")
      assert prepared_statement != nil
      assert %PreparedStatement{} = prepared_statement
      assert String.starts_with?(prepared_statement.name, "sv_")

      # Should return parse_pkt tuple with statement name
      assert [result_pkt] = result
      assert {:parse_pkt, server_name, result_bin} = result_pkt
      assert server_name == prepared_statement.name

      # Verify the result binary has the correct format
      assert <<?P, _len::32, ^server_name::binary-size(byte_size(prepared_statement.name)), 0,
               "select 1", 0, 0, 0>> = result_bin

      assert prepared_statement.parse_pkt == result_bin
    end

    test "bind message updates statement name" do
      parse_pkt =
        <<?P, 27::32, "server_stmt", 0, "select 1", 0, 0, 0>>

      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = Storage.put(Storage.new(), "test_stmt", prepared_statement)

      stream_state =
        MessageStreamer.stream_state(
          MessageStreamer.new_stream_state(PreparedStatements),
          handler_state: client_statements
        )

      # Bind message referencing prepared statement
      original_bin =
        <<?B, 21::32, 0, "test_stmt", 0, 0, 0, 0, 0, 0, 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should not change client_statements
      new_client_statements =
        MessageStreamer.stream_state(new_stream_state, :handler_state)

      original_client_statements =
        MessageStreamer.stream_state(stream_state, :handler_state)

      assert new_client_statements == original_client_statements

      # Should return bind_pkt tuple with statement name
      assert [result_pkt] = result
      assert {:bind_pkt, "server_stmt", result_bin, returned_parse_pkt} = result_pkt
      assert returned_parse_pkt == parse_pkt

      # Verify the result binary has the correct format
      assert <<?B, _len::32, 0, "server_stmt", 0, 0, 0, 0, 0, 0, 0>> = result_bin
    end

    test "describe message updates statement name" do
      parse_pkt =
        <<?P, 27::32, "server_stmt", 0, "select 1", 0, 0, 0>>

      prepared_statement = %PreparedStatement{name: "server_stmt", parse_pkt: parse_pkt}
      client_statements = Storage.put(Storage.new(), "test_stmt", prepared_statement)

      stream_state =
        MessageStreamer.stream_state(
          MessageStreamer.new_stream_state(PreparedStatements),
          handler_state: client_statements
        )

      original_bin = <<?D, 15::32, ?S, "test_stmt", 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should not change client_statements
      new_client_statements =
        MessageStreamer.stream_state(new_stream_state, :handler_state)

      original_client_statements =
        MessageStreamer.stream_state(stream_state, :handler_state)

      assert new_client_statements == original_client_statements

      # Should return describe_pkt tuple with statement name
      assert [result_pkt] = result
      assert {:describe_pkt, "server_stmt", result_bin} = result_pkt

      # Verify the result binary has the correct format
      assert <<?D, _len::32, ?S, "server_stmt", 0>> = result_bin
    end

    test "passthrough for message types we ignore", %{
      stream_state: stream_state
    } do
      # Execute message (should pass through)
      original_bin = <<?E, 9::32, 0, 0, 0, 0, 200>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [original_bin]
    end

    test "bind message with unknown statement name" do
      stream_state = MessageStreamer.new_stream_state(PreparedStatements)

      # Bind message referencing unknown statement
      original_bin =
        <<?B, 21::32, 0, "test_stmt", 0, 0, 0, 0, 0, 0, 0>>

      {:error, :prepared_statement_not_found} =
        MessageStreamer.handle_packets(stream_state, original_bin)
    end

    test "describe message with unknown statement name" do
      stream_state = MessageStreamer.new_stream_state(PreparedStatements)

      # Describe message for unknown statement
      original_bin = <<?D, 15::32, ?S, "test_stmt", 0>>

      {:error, :prepared_statement_not_found, "test_stmt"} =
        MessageStreamer.handle_packets(stream_state, original_bin)
    end

    test "describe message for unnamed statement is passed through unchanged", %{
      stream_state: stream_state
    } do
      # Describe message for unnamed statement (empty name)
      original_bin = <<?D, 6::32, ?S, 0>>

      {:ok, new_stream_state, result} =
        MessageStreamer.handle_packets(stream_state, original_bin)

      # Should return unchanged
      assert MessageStreamer.stream_state(new_stream_state, :handler_state) ==
               MessageStreamer.stream_state(stream_state, :handler_state)

      assert result == [original_bin]
    end

    test "parse message returns error when client limit is reached" do
      client_statements =
        Enum.reduce(1..PreparedStatements.client_limit(), Storage.new(), fn i, acc ->
          Storage.put(acc, "stmt_#{i}", %PreparedStatement{
            name: "server_stmt_#{i}",
            parse_pkt: <<>>
          })
        end)

      stream_state =
        MessageStreamer.stream_state(
          MessageStreamer.new_stream_state(PreparedStatements),
          handler_state: client_statements
        )

      bin =
        <<?P, 25::32, "test_stmt", 0, "select 1", 0, 0, 0>>

      assert {:error, :max_prepared_statements} =
               MessageStreamer.handle_packets(stream_state, bin)
    end

    test "parse message returns error for duplicate PS" do
      client_statements =
        Storage.put(Storage.new(), "stmt", %PreparedStatement{
          name: "server_stmt",
          parse_pkt: <<>>
        })

      stream_state =
        MessageStreamer.stream_state(
          MessageStreamer.new_stream_state(PreparedStatements),
          handler_state: client_statements
        )

      bin =
        <<?P, 20::32, "stmt", 0, "select 1", 0, 0, 0>>

      assert {:error, :duplicate_prepared_statement, "stmt"} =
               MessageStreamer.handle_packets(stream_state, bin)
    end

    test "parse message returns error when memory limit is reached" do
      # Create a large prepared statement that will push us over the memory limit
      large_query = String.duplicate("SELECT * FROM large_table WHERE col = 'data' AND ", 50_000)

      large_parse_pkt =
        <<?P, byte_size(large_query) + 20::32, "large_stmt", 0, large_query::binary, 0, 0, 0>>

      large_statement = %PreparedStatement{name: "large_stmt", parse_pkt: large_parse_pkt}

      client_statements = Storage.put(Storage.new(), "existing_stmt", large_statement)

      stream_state =
        MessageStreamer.stream_state(
          MessageStreamer.new_stream_state(PreparedStatements),
          handler_state: client_statements
        )

      # Try to add another statement that would exceed memory limit
      bin = <<?P, 25::32, "test_stmt", 0, "select 1", 0, 0, 0>>

      assert {:error, :max_prepared_statements_memory} =
               MessageStreamer.handle_packets(stream_state, bin)
    end

    test "streaming parsing works correctly regardless of packet sizes" do
      stream_state = MessageStreamer.new_stream_state(PreparedStatements)

      full_binary =
        [
          <<?P, 26::32, "test_stmt1", 0, "select 1", 0, 0, 0>>,
          <<?B, 22::32, 0, "test_stmt1", 0, 0, 0, 0, 0, 0, 0>>,
          <<?E, 9::32, 0, 0, 0, 0, 200>>,
          <<?S, 4::32>>,
          <<?C, 16::32, ?S, "test_stmt1", 0>>,
          <<?P, 26::32, "test_stmt2", 0, "select 2", 0, 0, 0>>,
          <<?B, 22::32, 0, "test_stmt2", 0, 0, 0, 0, 0, 0, 0>>,
          <<?E, 9::32, 0, 0, 0, 0, 201>>,
          <<?P, 26::32, "test_stmt3", 0, "select 3", 0, 0, 0>>,
          <<?D, 16::32, ?S, "test_stmt3", 0>>,
          <<?S, 4::32>>
        ]
        |> IO.iodata_to_binary()

      for chunk_size <- [1, 3, 7, 13, 23, 37] do
        {final_state, result} =
          full_binary
          |> chunk_binary(chunk_size)
          |> Enum.reduce({stream_state, []}, fn chunk, {state, acc} ->
            {:ok, new_state, chunk_result} = MessageStreamer.handle_packets(state, chunk)
            {new_state, acc ++ chunk_result}
          end)

        # Group consecutive binaries together while preserving order. Helps with making assertion easier
        grouped_result =
          Enum.reduce(result, [], fn
            raw_bin, [] when is_binary(raw_bin) ->
              [raw_bin]

            raw_bin, [last | rest] when is_binary(raw_bin) and is_binary(last) ->
              [<<last::binary, raw_bin::binary>> | rest]

            raw_bin, acc when is_binary(raw_bin) ->
              [raw_bin | acc]

            tuple, acc ->
              [tuple | acc]
          end)
          |> Enum.reverse()

        assert [
                 {:parse_pkt, _, _},
                 {:bind_pkt, _, _, _},
                 <<?E, 9::32, 0, 0, 0, 0, 200, ?S, 4::32>>,
                 {:close_pkt, _, _},
                 {:parse_pkt, _, _},
                 {:bind_pkt, _, _, _},
                 <<?E, 9::32, 0, 0, 0, 0, 201>>,
                 {:parse_pkt, _, _},
                 {:describe_pkt, _, _},
                 <<?S, 4::32>>
               ] = grouped_result

        assert MessageStreamer.stream_state(final_state, :pending_bin) == <<>>
        assert MessageStreamer.stream_state(final_state, :in_flight_pkt) == nil
      end
    end
  end

  defp chunk_binary(binary, chunk_size) when byte_size(binary) <= chunk_size do
    [binary]
  end

  defp chunk_binary(binary, chunk_size) do
    <<chunk::binary-size(chunk_size), rest::binary>> = binary
    [chunk | chunk_binary(rest, chunk_size)]
  end
end
