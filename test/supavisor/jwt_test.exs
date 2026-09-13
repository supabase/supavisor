defmodule Supavisor.JwtTest do
  use ExUnit.Case, async: true

  @subject Supavisor.Jwt

  @secret "my_secret_key"
  @wrong_secret "my_wrong_secret_key"

  describe "authorize/2" do
    test "returns claims for a valid token" do
      token = create_valid_jwt_token()
      assert {:ok, claims} = @subject.authorize(token, @secret)
      assert claims["role"] == "test"
    end

    test "raises an error for non-binary token" do
      assert_raise FunctionClauseError, fn ->
        @subject.authorize(123, @secret)
      end
    end

    test "returns signature_error for a wrong secret" do
      token = create_valid_jwt_token()
      assert {:error, :signature_error} = @subject.authorize(token, @wrong_secret)
    end
  end

  describe "authorize_dual/3" do
    @jwks_config %{trusted_issuer: "https://issuer.example", allowed_subs: [], expected_aud: nil}

    test "an HS-signed token always uses the HMAC path, jwks_config or not" do
      token = create_valid_jwt_token()

      assert {:ok, claims, :hmac} = @subject.authorize_dual(token, @secret, nil)
      assert claims["role"] == "test"

      assert {:ok, claims, :hmac} = @subject.authorize_dual(token, @secret, @jwks_config)
      assert claims["role"] == "test"
    end

    test "an HS-signed token with the wrong secret still fails on the HMAC path" do
      token = create_valid_jwt_token()

      assert {:error, :signature_error} = @subject.authorize_dual(token, @wrong_secret, nil)
    end

    test "a non-HMAC-alg token fails closed when jwks_config is nil" do
      token = build_rs256_shaped_token()

      assert {:error, :jwks_not_configured} = @subject.authorize_dual(token, @secret, nil)
    end

    test "a malformed token does not raise" do
      assert {:error, _reason} = @subject.authorize_dual("not-a-jwt", @secret, nil)
      assert {:error, _reason} = @subject.authorize_dual("not-a-jwt", @secret, @jwks_config)
    end

    test "fails closed (does not raise) for a non-binary token" do
      assert {:error, :token_not_a_string} = @subject.authorize_dual(123, @secret, nil)
    end
  end

  defp create_valid_jwt_token do
    @subject.Token.gen!(%{"role" => "test"}, @secret)
  end

  # Only the JWS header's `alg` is inspected before jwks_config is checked, so
  # this doesn't need a real signature — just a well-formed, decodable header.
  defp build_rs256_shaped_token do
    header = Base.url_encode64(JSON.encode!(%{"alg" => "RS256", "typ" => "JWT"}), padding: false)
    payload = Base.url_encode64(JSON.encode!(%{}), padding: false)
    signature = Base.url_encode64("fake-signature", padding: false)
    "#{header}.#{payload}.#{signature}"
  end
end
