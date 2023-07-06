defmodule Supavisor.ClientHandlerTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler

  describe "parse_user_info/1" do
    test "extracts the external_id from the username" do
      username = "test.user.external_id"
      {name, external_id} = ClientHandler.parse_user_info(username)
      assert name == "test.user"
      assert external_id == "external_id"
    end

    test "username consists only of external_id" do
      username = "external_id"
      {nil, external_id} = ClientHandler.parse_user_info(username)
      assert external_id == "external_id"
    end
  end

  describe "decode_startup_packet/1" do
    test "handles bad startup packets" do
      packet = <<0, 0, 0, 8, 0, 0, 0, 0, 3>>
      assert {:error, _} = ClientHandler.decode_startup_packet(packet)
    end

    test "handles valid startup packets" do
      payload = %{
        "DateStyle" => "ISO",
        "TimeZone" => "Asia/Tokyo",
        "client_encoding" => "UTF8",
        "database" => "mydbname",
        "extra_float_digits" => "2",
        "user" => "tenant.mytenant"
      }

      fields = Enum.reduce(payload, [], fn {k, v}, acc -> [k, v | acc] end) |> Enum.join(<<0>>)
      len = String.length(fields) + 4
      packet = <<len::integer-32, "prot"::binary, fields::binary>>
      assert {:ok, hello} = ClientHandler.decode_startup_packet(packet)
      assert hello[:payload]["user"] == "tenant.mytenant"
    end
  end
end
