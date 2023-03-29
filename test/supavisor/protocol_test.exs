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
    result = S.greetings(ps)

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
end
