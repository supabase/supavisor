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

  describe "parse_prepare_response/1" do
    test "extracts param OIDs and column names" do
      bin =
        parse_complete() <>
          parameter_description([23, 25]) <>
          row_description([{"id", 23}, {"name", 25}]) <>
          ready_for_query()

      assert {:ok, %{param_oids: [23, 25], columns: cols}} =
               WireDecoder.parse_prepare_response(bin)

      assert cols == [%{name: "id", oid: 23}, %{name: "name", oid: 25}]
    end

    test "no_data sets columns to nil (statement returns no rows)" do
      bin =
        parse_complete() <>
          parameter_description([]) <>
          no_data() <>
          ready_for_query()

      assert {:ok, %{param_oids: [], columns: nil}} = WireDecoder.parse_prepare_response(bin)
    end

    test "ErrorResponse surfaces as a PgError" do
      bin =
        parse_complete() <>
          error_response(%{?S => "ERROR", ?C => "42601", ?M => "syntax error"}) <>
          ready_for_query(?E)

      assert {:error, %PgError{code: "42601", severity: "ERROR"}} =
               WireDecoder.parse_prepare_response(bin)
    end
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
    test "true once the suffix appears" do
      assert WireDecoder.ready_for_query?(<<?2, 4::32>> <> ready_for_query())
    end

    test "false when buffer ends mid-packet" do
      refute WireDecoder.ready_for_query?(<<?2, 4::32>>)
      refute WireDecoder.ready_for_query?(<<?Z, 5::32>>)
    end
  end
end
