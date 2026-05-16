defmodule Supavisor.HttpSql.ErrorMapperTest do
  use ExUnit.Case, async: true

  alias Supavisor.Errors.CircuitBreakerError
  @subject Supavisor.HttpSql.ErrorMapper

  describe "Postgrex.Error → Neon body" do
    test "invalid_password → 401" do
      err = %Postgrex.Error{
        postgres: %{
          code: :invalid_password,
          pg_code: "28P01",
          severity: "FATAL",
          message: "password authentication failed for user \"u\""
        }
      }

      assert {401, body} = @subject.to_neon_error(err)
      assert body["message"] =~ "password authentication failed"
      assert body["code"] == "28P01"
      assert body["severity"] == "FATAL"
    end

    test "invalid_authorization_specification → 401" do
      err = %Postgrex.Error{
        postgres: %{code: :invalid_authorization_specification, pg_code: "28000", message: "no pg_hba"}
      }

      assert {401, _} = @subject.to_neon_error(err)
    end

    test "insufficient_privilege → 403" do
      err = %Postgrex.Error{postgres: %{code: :insufficient_privilege, pg_code: "42501", message: "x"}}
      assert {403, %{"code" => "42501"}} = @subject.to_neon_error(err)
    end

    test "unique_violation → 400 with constraint/table/detail" do
      err = %Postgrex.Error{
        postgres: %{
          code: :unique_violation,
          pg_code: "23505",
          severity: "ERROR",
          message: "duplicate key value violates unique constraint \"users_pkey\"",
          detail: "Key (id)=(1) already exists.",
          table: "users",
          constraint: "users_pkey",
          schema: "public",
          file: "indextuple.c",
          line: "59",
          routine: "_bt_check_unique"
        }
      }

      assert {400, body} = @subject.to_neon_error(err)
      assert body["code"] == "23505"
      assert body["table"] == "users"
      assert body["constraint"] == "users_pkey"
      assert body["schema"] == "public"
      assert body["detail"] =~ "already exists"
      assert body["file"] == "indextuple.c"
    end

    test "foreign_key_violation → 400" do
      err = %Postgrex.Error{
        postgres: %{
          code: :foreign_key_violation,
          pg_code: "23503",
          message: "fk violation",
          constraint: "fk_x",
          table: "orders"
        }
      }

      assert {400, %{"code" => "23503", "table" => "orders"}} = @subject.to_neon_error(err)
    end

    test "syntax_error → 400 with position" do
      err = %Postgrex.Error{
        postgres: %{
          code: :syntax_error,
          pg_code: "42601",
          message: "syntax error at or near \"FOO\"",
          position: "8"
        }
      }

      assert {400, body} = @subject.to_neon_error(err)
      assert body["code"] == "42601"
      assert body["position"] == "8"
    end

    test "drops nil keys from the body" do
      err = %Postgrex.Error{postgres: %{code: :syntax_error, pg_code: "42601", message: "x"}}
      assert {400, body} = @subject.to_neon_error(err)
      refute Map.has_key?(body, "detail")
      refute Map.has_key?(body, "hint")
      refute Map.has_key?(body, "schema")
    end

    test "Postgrex.Error without postgres field → 500" do
      err = %Postgrex.Error{message: "weird"}
      assert {500, %{"code" => "internal_error", "message" => "weird"}} = @subject.to_neon_error(err)
    end
  end

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
end
