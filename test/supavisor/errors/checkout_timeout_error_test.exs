defmodule Supavisor.Errors.CheckoutTimeoutErrorTest do
  use ExUnit.Case, async: true

  alias Supavisor.Errors.CheckoutTimeoutError

  describe "error_message/1" do
    test "includes timeout duration and mode for transaction mode" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 5000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "checkout timed out after 5000ms"
      assert message =~ "Transaction mode"
      assert message =~ "connection pool cannot serve them fast enough"
    end

    test "includes timeout duration and mode for session mode" do
      error = %CheckoutTimeoutError{mode: :session, timeout_ms: 3000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "checkout timed out after 3000ms"
      assert message =~ "Session mode"
    end

    test "provides actionable guidance about database availability" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "Ensuring your database is available"
    end

    test "provides actionable guidance about slow queries" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "Tracking down slow queries"
    end

    test "includes mode-specific pool_size hint for transaction mode" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "pool_size"
      assert message =~ "Transaction mode allows connection reuse"
    end

    test "includes mode-specific pool_size hint for session mode" do
      error = %CheckoutTimeoutError{mode: :session, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "pool_size"
      assert message =~ "Session mode each client holds a dedicated connection"
    end

    test "provides actionable guidance about checkout timeout" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "Increasing the checkout timeout"
      assert message =~ "increases latency"
    end

    test "includes documentation URL" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      message = CheckoutTimeoutError.error_message(error)

      assert message =~ "https://supabase.com/docs/guides/database/connecting-to-postgres"
    end
  end

  describe "log_message/1" do
    test "returns concise message for logging" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 5000, code: "ECHECKOUTTIMEOUT"}
      log_msg = CheckoutTimeoutError.log_message(error)

      assert log_msg == "(ECHECKOUTTIMEOUT) checkout timeout after 5000ms in Transaction mode"
    end

    test "formats session mode correctly" do
      error = %CheckoutTimeoutError{mode: :session, timeout_ms: 2500, code: "ECHECKOUTTIMEOUT"}
      log_msg = CheckoutTimeoutError.log_message(error)

      assert log_msg == "(ECHECKOUTTIMEOUT) checkout timeout after 2500ms in Session mode"
    end

    test "is shorter than error_message for reduced log verbosity" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 5000, code: "ECHECKOUTTIMEOUT"}

      log_msg = CheckoutTimeoutError.log_message(error)
      error_msg = CheckoutTimeoutError.error_message(error)

      assert String.length(log_msg) < String.length(error_msg)
    end
  end

  describe "log_level/1" do
    test "returns warning level since timeouts are often transient" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      assert CheckoutTimeoutError.log_level(error) == :warning
    end
  end

  describe "message/1" do
    test "prefixes error_message with error code in parentheses" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      full_message = CheckoutTimeoutError.message(error)

      assert full_message =~ "(ECHECKOUTTIMEOUT)"
      assert full_message =~ "checkout timed out after 1000ms"
    end
  end

  describe "postgres_error/1" do
    test "returns fatal postgres error map with correct structure" do
      error = %CheckoutTimeoutError{mode: :transaction, timeout_ms: 1000, code: "ECHECKOUTTIMEOUT"}
      pg_error = CheckoutTimeoutError.postgres_error(error)

      assert pg_error["S"] == "FATAL"
      assert pg_error["C"] == "XX000"
      assert pg_error["M"] =~ "ECHECKOUTTIMEOUT"
      assert pg_error["M"] =~ "checkout timed out"
    end
  end

  describe "exception/1" do
    test "creates struct with provided fields and default code" do
      error = CheckoutTimeoutError.exception(mode: :session, timeout_ms: 2500)

      assert error.mode == :session
      assert error.timeout_ms == 2500
      assert error.code == "ECHECKOUTTIMEOUT"
    end
  end
end
