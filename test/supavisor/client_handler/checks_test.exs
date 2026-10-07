defmodule Supavisor.ClientHandler.ChecksTest do
  use ExUnit.Case, async: true

  alias Supavisor.ClientHandler.Checks
  alias Supavisor.Errors.{AddressNotAllowedError, ClientSocketClosedError, TenantBannedError}

  defp banned_tenant(banned_until) do
    %{
      tenant: %{
        banned_at: ~U[2026-01-01 00:00:00Z],
        ban_reason: "test reason",
        banned_until: banned_until
      }
    }
  end

  describe "check_tenant_not_banned/2 with banned_until" do
    test "allows connection when now is after banned_until" do
      banned_until = ~U[2026-04-08 12:00:00Z]
      now = ~U[2026-04-08 12:00:01Z]
      assert :ok = Checks.check_tenant_not_banned(banned_tenant(banned_until), now)
    end

    test "tenant is still banned at the exact time of banned_until" do
      banned_until = ~U[2026-04-08 12:00:00Z]

      assert {:error, %TenantBannedError{ban_reason: "test reason"}} =
               Checks.check_tenant_not_banned(banned_tenant(banned_until), banned_until)
    end

    test "tenant is banned when now is before banned_until" do
      banned_until = ~U[2026-04-08 12:00:00Z]
      now = ~U[2026-04-08 11:59:59Z]

      assert {:error, %TenantBannedError{ban_reason: "test reason"}} =
               Checks.check_tenant_not_banned(banned_tenant(banned_until), now)
    end
  end

  describe "check_tenant_not_banned/2 without banned_until" do
    test "returns error when tenant is banned with no expiry" do
      data = %{
        tenant: %{banned_at: ~U[2026-01-01 00:00:00Z], ban_reason: "permanent", banned_until: nil}
      }

      assert {:error, %TenantBannedError{ban_reason: "permanent"}} =
               Checks.check_tenant_not_banned(data)
    end

    test "allows connection when tenant is not banned" do
      data = %{tenant: %{banned_at: nil, ban_reason: nil, banned_until: nil}}
      assert :ok = Checks.check_tenant_not_banned(data)
    end
  end

  describe "check_address_allowed/2" do
    setup do
      {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, active: false)
      {:ok, port} = :inet.port(listen)
      {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, active: false)
      {:ok, server} = :gen_tcp.accept(listen)

      on_exit(fn ->
        :gen_tcp.close(client)
        :gen_tcp.close(listen)
      end)

      %{data: %{sock: {:gen_tcp, server}, mode: :transaction}}
    end

    test "allows address in allow_list", %{data: data} do
      info = %{tenant: %{allow_list: ["127.0.0.1/32"]}}
      assert :ok = Checks.check_address_allowed(data, info)
    end

    test "rejects address not in allow_list", %{data: data} do
      info = %{tenant: %{allow_list: ["10.0.0.0/8"]}}

      assert {:error, %AddressNotAllowedError{address: {127, 0, 0, 1}}} =
               Checks.check_address_allowed(data, info)
    end

    test "returns socket closed error when the client socket is closed", %{data: data} do
      {:gen_tcp, server} = data.sock
      :ok = :gen_tcp.close(server)
      info = %{tenant: %{allow_list: ["0.0.0.0/0", "::/0"]}}

      assert {:error,
              %ClientSocketClosedError{
                mode: :transaction,
                client_state: :handshake,
                reason: :einval
              }} = Checks.check_address_allowed(data, info)
    end
  end
end
