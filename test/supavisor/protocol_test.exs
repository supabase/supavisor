defmodule Supavisor.ProtocolTest do
  use ExUnit.Case, async: true
  alias Supavisor.Protocol.Server, as: S

  @initial_data %{
    "DateStyle" => "ISO, MDY",
    "IntervalStyle" => "postgres",
    "TimeZone" => "UTC",
    "application_name" => "supavisor",
    "client_encoding" => "UTF8",
    "default_transaction_read_only" => "off",
    "in_hot_standby" => "off",
    "integer_datetimes" => "on",
    "is_superuser" => "on",
    "server_encoding" => "UTF8",
    "server_version" => "14.6 (Debian 14.6-1.pgdg110+1)",
    "session_authorization" => "postgres",
    "standard_conforming_strings" => "on"
  }

  @auth_bin_error <<69, 0, 0, 0, 111, 83, 70, 65, 84, 65, 76, 0, 86, 70, 65, 84, 65, 76, 0, 67,
                    50, 56, 80, 48, 49, 0, 77, 112, 97, 115, 115, 119, 111, 114, 100, 32, 97, 117,
                    116, 104, 101, 110, 116, 105, 99, 97, 116, 105, 111, 110, 32, 102, 97, 105,
                    108, 101, 100, 32, 102, 111, 114, 32, 117, 115, 101, 114, 32, 34, 116, 101,
                    115, 116, 95, 119, 114, 111, 110, 103, 95, 117, 115, 101, 114, 34, 0, 70, 97,
                    117, 116, 104, 46, 99, 0, 76, 51, 51, 53, 0, 82, 97, 117, 116, 104, 95, 102,
                    97, 105, 108, 101, 100, 0, 0>>

  test "encode_parameter_status/1" do
    result = S.encode_parameter_status(@initial_data)

    for {key, value} <- @initial_data do
      assert :erlang.is_binary(key)
      assert :erlang.is_binary(value)
      encoded = S.encode_pkt(:parameter_status, key, value)
      assert Enum.member?(result, encoded)
    end
  end

  test "encode_pkt/3" do
    key = "TimeZone"
    value = "UTC"
    result = S.encode_pkt(:parameter_status, key, value)

    assert result == [<<?S, 17::32>>, [key, <<0>>, value, <<0>>]]
  end

  test "backend_key_data/0" do
    result = S.backend_key_data()
    payload = Enum.at(result, 1)
    len = byte_size(payload) + 4

    assert [
             %S.Pkt{
               tag: :backend_key_data,
               len: 13,
               payload: %{procid: _, secret: _}
             }
           ] = S.decode(result |> IO.iodata_to_binary())

    assert hd(result) == <<?K, len::32>>
    assert byte_size(payload) == 8
  end

  test "greetings/1" do
    ps = S.encode_parameter_status(@initial_data)

    dec =
      S.greetings(ps)
      |> IO.iodata_to_binary()
      |> S.decode()

    ready_for_query_pos = Enum.at(dec, -1)
    backend_key_data_pos = Enum.at(dec, -2)
    assert %S.Pkt{tag: :ready_for_query} = ready_for_query_pos
    assert %S.Pkt{tag: :backend_key_data} = backend_key_data_pos
    tags = Enum.map(dec, & &1.tag)
    assert Enum.count(tags, &(&1 == :parameter_status)) == 13
    assert Enum.count(tags, &(&1 == :backend_key_data)) == 1
    assert Enum.count(tags, &(&1 == :ready_for_query)) == 1
  end

  test "decode_payload for error_response" do
    assert S.decode(@auth_bin_error) == [
             %Supavisor.Protocol.Server.Pkt{
               tag: :error_response,
               len: 112,
               payload: [
                 "SFATAL",
                 "VFATAL",
                 "C28P01",
                 "Mpassword authentication failed for user \"test_wrong_user\"",
                 "Fauth.c",
                 "L335",
                 "Rauth_failed"
               ]
             }
           ]
  end
end
