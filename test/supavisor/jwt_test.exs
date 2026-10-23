defmodule Supavisor.JwtTest do
  use ExUnit.Case, async: true

  @subject Supavisor.Jwt

  @secret "my_secret_key"
  @wrong_secret "my_wrong_secret_key"

  describe "authorize_dual/3" do
    @jwks_config %{trusted_issuer: "https://issuer.example", allowed_subs: [], expected_aud: nil}

    test "an HS-signed token always uses the HMAC path, jwks_config or not" do
      token = create_valid_jwt_token()

      assert {:ok, :hmac, claims} = @subject.authorize_dual(token, @secret, nil)
      assert claims["role"] == "test"

      assert {:ok, :hmac, claims} = @subject.authorize_dual(token, @secret, @jwks_config)
      assert claims["role"] == "test"
    end

    test "an HS-signed token with the wrong secret still fails on the HMAC path" do
      token = create_valid_jwt_token()

      assert {:error, :hmac, :signature_error} =
               @subject.authorize_dual(token, @wrong_secret, nil)
    end

    test "a non-HMAC-alg token fails when jwks_config is nil" do
      token = build_rs256_shaped_token()

      assert {:error, :jwks, :jwks_not_configured} = @subject.authorize_dual(token, @secret, nil)
    end

    test "a malformed token does not raise" do
      assert {:error, :unknown, _reason} = @subject.authorize_dual("not-a-jwt", @secret, nil)

      assert {:error, :unknown, _reason} =
               @subject.authorize_dual("not-a-jwt", @secret, @jwks_config)
    end

    test "a token without a header alg is :unknown" do
      no_alg = Base.url_encode64(JSON.encode!(%{"typ" => "JWT"}), padding: false) <> ".e30.sig"

      assert {:error, :unknown, :missing_alg} = @subject.authorize_dual(no_alg, @secret, nil)
    end

    test "fails for a non-binary token" do
      assert {:error, :unknown, :token_not_a_string} = @subject.authorize_dual(123, @secret, nil)
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
