defmodule Supavisor.ErrorFaultTest do
  use ExUnit.Case, async: true

  alias Supavisor.Errors

  defp fault(error), do: error.__struct__.fault(error)

  describe "fault/1" do
    test "immediate rejections of a bad request are the user's" do
      for error <- [
            %Errors.WrongPasswordError{user: "u"},
            %Errors.TenantOrUserNotFoundError{},
            %Errors.SslRequiredError{user: "u"},
            %Errors.TenantBannedError{},
            %Errors.AddressNotAllowedError{address: "1.2.3.4"},
            %Errors.InvalidUserInfoError{},
            %Errors.NoTenantIdentifierError{},
            %Errors.StartupMessageError{},
            %Errors.StartupPacketTooLargeError{packet_size: 1},
            %Errors.SslHandshakeError{reason: :closed},
            %Errors.AuthProtocolError{},
            %Errors.PasswordChangedError{user: "u"},
            %Errors.JitUnauthorizedError{}
          ] do
        assert fault(error) == :user, inspect(error)
      end
    end

    test "user-side errors that are slow by design are user_timeout" do
      for error <- [
            %Errors.HandshakeTimeoutError{},
            %Errors.AuthTimeoutError{context: :auth_password_wait},
            Errors.MaxConnectionsError.new(:transaction, 10),
            Errors.MaxConnectionsError.new(:session, 10),
            %Errors.CheckoutTimeoutError{reason: :pool_exhausted}
          ] do
        assert fault(error) == :user_timeout, inspect(error)
      end
    end

    test "the client leaving is a client_abort" do
      assert fault(%Errors.ClientSocketClosedError{client_state: :handshake}) == :client_abort
    end

    test "checkout timeout depends on which wait timed out" do
      assert fault(%Errors.CheckoutTimeoutError{reason: :pool_exhausted}) == :user_timeout
      assert fault(%Errors.CheckoutTimeoutError{reason: :unresponsive}) == :supavisor
      assert fault(%Errors.CheckoutTimeoutError{reason: nil}) == :supavisor
    end

    test "circuit breaker depends on the operation that tripped" do
      assert fault(%Errors.CircuitBreakerError{operation: :auth_error}) == :user
      assert fault(%Errors.CircuitBreakerError{operation: :get_secrets}) == :supavisor
      assert fault(%Errors.CircuitBreakerError{operation: :db_connection}) == :supavisor
    end

    test "failures on our side are supavisor's" do
      for error <- [
            %Errors.AuthQueryError{},
            %Errors.DbHandlerExitedError{reason: :boom},
            %Errors.CheckoutRetriesExhaustedError{},
            %Errors.SubscribeRetriesExhaustedError{},
            %Errors.FailedToStartProxyConnectionError{},
            %Errors.PoolCheckoutError{reason: :boom},
            %Errors.JitRequestFailedError{user: "u", reason: :request_crashed}
          ] do
        assert fault(error) == :supavisor, inspect(error)
      end
    end

    test "every error module declares a valid fault" do
      {:ok, modules} = :application.get_key(:supavisor, :modules)

      error_modules =
        Enum.filter(modules, fn module ->
          String.starts_with?(Atom.to_string(module), "Elixir.Supavisor.Errors.")
        end)

      assert error_modules != []

      for module <- error_modules do
        assert module.fault(struct(module)) in [:user, :user_timeout, :supavisor, :client_abort],
               inspect(module)
      end
    end
  end
end
