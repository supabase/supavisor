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
    expected_payload = [key, <<0>>, value, <<0>>]
    len = IO.iodata_length(expected_payload) + 4

    assert result == [<<?S, 17>>, ["TimeZone", <<0>>, "UTC", <<0>>]]
    assert hd(result) == <<?S, len::integer-32>>
    assert Enum.at(result, 1) == expected_payload
  end

  test "backend_key_data/0" do
    result = S.backend_key_data()
    payload = Enum.at(result, 1)
    len = byte_size(payload) + 4

    assert is_list(result)
    assert hd(result) == <<?K, len::integer-32>>
    assert byte_size(payload) == 8
  end

  test "greetings/1" do
    ps = S.encode_parameter_status(@initial_data)
    result = S.greetings(ps)

    assert is_list(result)
    assert hd(result) == ps
    assert IO.iodata_length(Enum.at(result, 1)) == 13
    assert Enum.at(result, 2) == <<?Z, 5::integer-32, ?I>>
  end
end
