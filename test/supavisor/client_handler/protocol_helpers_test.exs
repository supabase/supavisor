defmodule Supavisor.ClientHandler.ProtocolHelpersTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler.ProtocolHelpers

  describe "extract_and_validate_user_info/1" do
    test "extracts valid forwarded IPv4 and IPv6 addresses" do
      for client_ip <- ["192.0.2.10", "2001:db8::10"] do
        payload = %{
          "user" => "postgres.tenant",
          "database" => "postgres",
          "options" => %{"client_ip" => client_ip}
        }

        assert {:ok, {:single, {"postgres", "tenant", "postgres", nil, false, nil, ^client_ip}}} =
                 ProtocolHelpers.extract_and_validate_user_info(payload)
      end
    end

    test "ignores a malformed forwarded address" do
      payload = %{
        "user" => "postgres.tenant",
        "database" => "postgres",
        "options" => %{"client_ip" => "not-an-ip"}
      }

      assert {:ok, {:single, {"postgres", "tenant", "postgres", nil, false, nil, nil}}} =
               ProtocolHelpers.extract_and_validate_user_info(payload)
    end
  end

  describe "resolve_peer_ip/3" do
    test "uses a forwarded address only for a local listener" do
      assert ProtocolHelpers.resolve_peer_ip("127.0.0.1", "192.0.2.10", true) ==
               "192.0.2.10"

      assert ProtocolHelpers.resolve_peer_ip("127.0.0.1", "192.0.2.10", false) ==
               "127.0.0.1"
    end

    test "falls back to the socket peer when the forwarded address is missing" do
      assert ProtocolHelpers.resolve_peer_ip("127.0.0.1", nil, true) == "127.0.0.1"
    end
  end
end
