defmodule Supavisor.HttpSql.WireDecoderTest do
  use ExUnit.Case, async: true

  alias Supavisor.HttpSql.{PgError, WireDecoder}

  defp parse_complete, do: <<?1, 4::32>>
  defp bind_complete, do: <<?2, 4::32>>
  defp ready_for_query(status \\ ?I), do: <<?Z, 5::32, status>>
  defp no_data, do: <<?n, 4::32>>

  defp parameter_description(oids) when is_list(oids) do
    count = length(oids)
    payload = <<count::16>> <> for(oid <- oids, into: <<>>, do: <<oid::32>>)
    <<?t, byte_size(payload) + 4::32>> <> payload
  end

  defp row_description(fields) do
    count = length(fields)

    field_bin =
      for {name, oid} <- fields, into: <<>> do
        # field name (null-terminated) + table_oid + attr + data_type_oid +
        # data_type_size + type_mod + format_code
        <<name::binary, 0, 0::32, 0::16, oid::32, -1::16-signed, -1::32-signed, 0::16>>
      end

    payload = <<count::16>> <> field_bin
    <<?T, byte_size(payload) + 4::32>> <> payload
  end

  defp data_row(values) do
    count = length(values)

    val_bin =
      for v <- values, into: <<>> do
        case v do
          nil -> <<-1::32-signed>>
          bin -> <<byte_size(bin)::32-signed, bin::binary>>
        end
      end

    payload = <<count::16>> <> val_bin
    <<?D, byte_size(payload) + 4::32>> <> payload
  end

  defp command_complete(tag) do
    payload = tag <> <<0>>
    <<?C, byte_size(payload) + 4::32>> <> payload
  end

  defp error_response(fields) do
    payload =
      for {k, v} <- fields, into: <<>> do
        <<k::utf8, v::binary, 0>>
      end <> <<0>>

    <<?E, byte_size(payload) + 4::32>> <> payload
  end

  describe "parse_execute_response/1" do
    test "simple SELECT with two rows" do
      bin =
        bind_complete() <>
          row_description([{"n", 23}]) <>
          data_row(["1"]) <>
          data_row(["2"]) <>
          command_complete("SELECT 2") <>
          ready_for_query()

      assert {:ok, result} = WireDecoder.parse_execute_response(bin)
      assert result.rows == [["1"], ["2"]]
      assert result.command == "SELECT"
      assert result.num_rows == 2
      assert result.columns == [%{name: "n", oid: 23}]
    end

    test "NULL column value comes through as nil" do
      bin =
        bind_complete() <>
          row_description([{"a", 23}, {"b", 25}]) <>
          data_row(["1", nil]) <>
          command_complete("SELECT 1") <>
          ready_for_query()

      assert {:ok, %{rows: [["1", nil]]}} = WireDecoder.parse_execute_response(bin)
    end

    test "INSERT command tag with OID strips the OID and reads row count" do
      bin =
        bind_complete() <>
          command_complete("INSERT 0 5") <>
          ready_for_query()

      assert {:ok, %{command: "INSERT", num_rows: 5}} = WireDecoder.parse_execute_response(bin)
    end

    test "UPDATE / DELETE row count" do
      for tag <- ["UPDATE 7", "DELETE 3"] do
        bin =
          bind_complete() <> command_complete(tag) <> ready_for_query()

        {:ok, result} = WireDecoder.parse_execute_response(bin)
        assert result.num_rows in [7, 3]
        assert result.command in ["UPDATE", "DELETE"]
      end
    end

    test "BEGIN / COMMIT have no row count" do
      for tag <- ["BEGIN", "COMMIT"] do
        bin = bind_complete() <> command_complete(tag) <> ready_for_query()
        {:ok, %{command: ^tag, num_rows: 0}} = WireDecoder.parse_execute_response(bin)
      end
    end

    test "ErrorResponse halts and returns PgError" do
      bin =
        bind_complete() <>
          error_response(%{?S => "ERROR", ?C => "23505", ?M => "duplicate key"}) <>
          ready_for_query(?E)

      assert {:error, %PgError{code: "23505", message: "duplicate key"}} =
               WireDecoder.parse_execute_response(bin)
    end

    test "empty query response yields zero rows" do
      bin =
        bind_complete() <>
          <<?I, 4::32>> <>
          ready_for_query()

      assert {:ok, %{command: "", num_rows: 0, rows: []}} =
               WireDecoder.parse_execute_response(bin)
    end
  end

  describe "ready_for_query?/1" do
    test "true once a complete buffer ending in RFQ is received" do
      assert WireDecoder.ready_for_query?(<<?2, 4::32>> <> ready_for_query())
    end

    test "false when buffer ends mid-packet" do
      refute WireDecoder.ready_for_query?(<<?2, 4::32>>)
      refute WireDecoder.ready_for_query?(<<?Z, 5::32>>)
    end

    # CRIT-3 regression: a DataRow column whose text value contains the byte
    # sequence `Z\x00\x00\x00\x05` used to false-positive a substring scan
    # for `<<?Z, 5::32>>`, making the receive loop return a truncated buffer
    # mid-query. The framed-decode replacement walks complete packets and
    # only returns true when the LAST decoded packet is :ready_for_query.
    test "false when a DataRow column embeds the RFQ byte sequence" do
      # A 5-byte column value `Z\x00\x00\x00\x05` — would have triggered
      # the old substring match at offset (header + value-length). Wrap it
      # in a fully-framed DataRow followed by NOTHING (no RFQ).
      poison = <<?Z, 0, 0, 0, 5>>

      bin =
        bind_complete() <>
          row_description([{"col", 25}]) <>
          data_row([poison])

      # No RFQ at the tail → must NOT be considered ready.
      refute WireDecoder.ready_for_query?(bin)
    end

    test "true even after a poison-bearing DataRow when RFQ does arrive" do
      poison = <<?Z, 0, 0, 0, 5, "more">>

      bin =
        bind_complete() <>
          row_description([{"col", 25}]) <>
          data_row([poison]) <>
          command_complete("SELECT 1") <>
          ready_for_query()

      assert WireDecoder.ready_for_query?(bin)

      # And the full decode round-trips the value correctly.
      assert {:ok, %{rows: [[^poison]]}} = WireDecoder.parse_execute_response(bin)
    end

    test "malformed packet header surfaces safely (no raise)" do
      # Packet `Z` with length 1 — payload_len would be -3, causing a
      # negative binary-size match on the raw stream. safe_decode catches
      # the raise and we return false.
      refute WireDecoder.ready_for_query?(<<?Z, 1::32, ?I>>)
    end
  end

  describe "parse_execute_response/1 robustness" do
    # A `Z` header claiming length 1 (payload_len = -3) — Server.decode_pkt's
    # binary-size match fails (rather than raises) on modern OTP, so the
    # outer decode returns the input as `rest` and we surface :incomplete.
    test "malformed length header surfaces as :incomplete (no raise)" do
      assert {:error, :incomplete} =
               WireDecoder.parse_execute_response(<<?Z, 1::32, ?I>>)
    end

    # Defensive: any input that gets through framing but isn't a real
    # response stream must not crash the request process. The fallback
    # path is exercised by feeding partial-frame bytes.
    test "partial header (4 bytes) returns :incomplete" do
      assert {:error, :incomplete} = WireDecoder.parse_execute_response(<<?Z, 0, 0, 0>>)
    end
  end
end
