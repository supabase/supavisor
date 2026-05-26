defmodule Supavisor.HttpSql.ErrorMapperTest do
  use ExUnit.Case, async: true

  alias Supavisor.Errors.CircuitBreakerError
  alias Supavisor.HttpSql.PgError
  @subject Supavisor.HttpSql.ErrorMapper

  describe "DBConnection / timeout" do
    test "ConnectionError → 503" do
      err = %DBConnection.ConnectionError{message: "could not connect"}
      assert {503, %{"code" => "connection_error", "message" => "could not connect"}} =
               @subject.to_neon_error(err)
    end

    test ":timeout → 503" do
      assert {503, %{"code" => "timeout"}} = @subject.to_neon_error(:timeout)
    end
  end

  describe "CircuitBreaker" do
    test "CircuitBreakerError → 503 with blocked_until" do
      err = %CircuitBreakerError{
        operation: :auth_error,
        blocked_until: ~U[2026-05-15 14:30:00Z]
      }

      assert {503, body} = @subject.to_neon_error(err)
      assert body["code"] == "circuit_open"
      assert body["operation"] == "auth_error"
      assert body["blocked_until"] == "2026-05-15T14:30:00Z"
    end
  end

  describe "application-level errors" do
    test "row_limit_exceeded → 413" do
      assert {413, body} = @subject.to_neon_error({:row_limit_exceeded, 10_000})
      assert body["code"] == "row_limit_exceeded"
      assert body["limit"] == 10_000
    end

    test "params_encoding → 400" do
      assert {400, %{"code" => "params_encoding"}} =
               @subject.to_neon_error({:params_encoding, :argument_error})
    end

    test "malformed_request → 400" do
      assert {400, %{"code" => "malformed_request"}} =
               @subject.to_neon_error({:malformed_request, :missing_query})
    end

    test "unauthorized → 401" do
      assert {401, %{"code" => "unauthorized"}} =
               @subject.to_neon_error({:unauthorized, "bad user"})
    end

    test "forbidden → 403 with reason as code" do
      assert {403, %{"code" => "banned"}} =
               @subject.to_neon_error({:forbidden, "banned"})
    end

    test "feature_disabled → 404" do
      assert {404, %{"code" => "feature_disabled"}} =
               @subject.to_neon_error({:feature_disabled, :global})
    end
  end

  describe "fallback" do
    test "unknown error → 500 with generic message (no inspected term in body)" do
      assert {500, body} = @subject.to_neon_error(:some_unknown_thing)
      assert body["code"] == "internal_error"
      assert body["message"] == "internal error"
      # The fallback must NOT echo the unknown term back to the HTTP
      # response — it could carry conns, secrets, or internal structs.
      refute Map.has_key?(body, "detail")
    end

    test "secret-bearing struct doesn't leak into response body" do
      fake_error_with_password =
        {:weird_term, %{conn_string: "postgres://u:SUPERSECRET@h/d"}}

      assert {500, body} = @subject.to_neon_error(fake_error_with_password)
      refute body["message"] =~ "SUPERSECRET"
      refute Map.has_key?(body, "detail")
    end
  end

  describe "PgError → Neon body (wire-decoder source)" do
    test "invalid_password (28P01) → 401" do
      err =
        PgError.exception(%{
          "S" => "FATAL",
          "C" => "28P01",
          "M" => "password authentication failed for user \"u\""
        })

      assert {401, body} = @subject.to_neon_error(err)
      assert body["code"] == "28P01"
      assert body["severity"] == "FATAL"
      assert body["message"] =~ "password authentication failed"
    end

    test "invalid_authorization_specification (28000) → 401" do
      err = PgError.exception(%{"C" => "28000", "M" => "no auth"})
      assert {401, _} = @subject.to_neon_error(err)
    end

    test "insufficient_privilege (42501) → 403" do
      err = PgError.exception(%{"C" => "42501", "M" => "permission denied"})
      assert {403, _} = @subject.to_neon_error(err)
    end

    test "syntax error (42601) → 400 with full field mapping" do
      err =
        PgError.exception(%{
          "S" => "ERROR",
          "C" => "42601",
          "M" => "syntax error at or near \"FROM\"",
          "P" => "8",
          "F" => "scan.l",
          "L" => "1158",
          "R" => "scanner_yyerror"
        })

      assert {400, body} = @subject.to_neon_error(err)
      assert body["code"] == "42601"
      assert body["position"] == "8"
      assert body["file"] == "scan.l"
      assert body["line"] == "1158"
      assert body["routine"] == "scanner_yyerror"
    end

    test "drops nil fields from body" do
      err = PgError.exception(%{"C" => "23505", "M" => "duplicate key"})
      {_, body} = @subject.to_neon_error(err)
      refute Map.has_key?(body, "detail")
      refute Map.has_key?(body, "hint")
      assert body["message"] == "duplicate key"
    end

    test "unknown SQLSTATE → 400 (default)" do
      err = PgError.exception(%{"C" => "XX001", "M" => "internal"})
      assert {400, _} = @subject.to_neon_error(err)
    end
  end
end
