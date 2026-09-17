defmodule Supavisor.ClientHandler.ProtocolHelpersTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler.ProtocolHelpers
  alias Supavisor.Protocol.StartupOptions

  describe "extract_and_validate_user_info/1" do
    test "returns nil client_ip when the option is absent" do
      payload = %{"user" => "postgres.some_tenant", "options" => %{"jit" => "true"}}

      assert {:ok, {_type, {"postgres", "some_tenant", nil, nil, true, nil, nil}}} =
               ProtocolHelpers.extract_and_validate_user_info(payload)
    end

    test "returns nil client_ip when there are no options" do
      payload = %{"user" => "postgres.some_tenant"}

      assert {:ok, {_type, {"postgres", "some_tenant", nil, nil, false, nil, nil}}} =
               ProtocolHelpers.extract_and_validate_user_info(payload)
    end

    test "extracts client_ip alongside jit and client_tls" do
      payload = %{
        "user" => "postgres.some_tenant",
        "options" => %{"jit" => "true", "client_tls" => "true", "client_ip" => "203.0.113.9"}
      }

      assert {:ok, {_type, {"postgres", "some_tenant", nil, nil, true, true, "203.0.113.9"}}} =
               ProtocolHelpers.extract_and_validate_user_info(payload)
    end

    test "round-trips client_ip through the startup options wire format" do
      # This is the format DbHandler.send_startup/4 uses when forwarding a
      # proxied connection to the pool node.
      encoded =
        StartupOptions.encode(%{
          "jit" => "true",
          "client_tls" => "true",
          "client_ip" => "2001:db8::1"
        })

      payload = %{"user" => "postgres.some_tenant", "options" => StartupOptions.parse(encoded)}

      assert {:ok, {_type, {"postgres", "some_tenant", nil, nil, true, true, "2001:db8::1"}}} =
               ProtocolHelpers.extract_and_validate_user_info(payload)
    end
  end

  describe "effective_peer_ip/3" do
    @socket_ip "10.0.0.5"

    test "uses the forwarded IPv4 address on a local listener" do
      assert ProtocolHelpers.effective_peer_ip(true, "203.0.113.9", @socket_ip) == "203.0.113.9"
    end

    test "uses the forwarded IPv6 address on a local listener" do
      assert ProtocolHelpers.effective_peer_ip(true, "2001:db8::1", @socket_ip) == "2001:db8::1"
    end

    test "ignores the forwarded address on a non-local (public) listener" do
      assert ProtocolHelpers.effective_peer_ip(false, "203.0.113.9", @socket_ip) == @socket_ip
    end

    test "falls back to the socket peer when nothing was forwarded" do
      assert ProtocolHelpers.effective_peer_ip(true, nil, @socket_ip) == @socket_ip
      assert ProtocolHelpers.effective_peer_ip(false, nil, @socket_ip) == @socket_ip
    end

    test "falls back to the socket peer when the forwarded value is not an IP" do
      for bad <- ["", "undefined", "not-an-ip", "203.0.113", "203.0.113.9 ", "example.com"] do
        assert ProtocolHelpers.effective_peer_ip(true, bad, @socket_ip) == @socket_ip,
               "expected fallback for #{inspect(bad)}"
      end
    end
  end
end
