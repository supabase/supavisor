defmodule Supavisor.JWT.JWKSTest do
  # Starts the real, named `Supavisor.JWT.JWKS.Strategy` singleton and mutates
  # global `Application` env (`:api_jwks_config`) plus the global Tesla.Mock —
  # must not run concurrently with other tests touching the same state.
  use ExUnit.Case, async: false

  import Supavisor.JWKSHelper

  alias Supavisor.JWT.JWKS

  setup_all do
    Map.put(generate_rsa_keypair(), :ec, generate_ec_keypair())
  end

  # Mixed RSA + EC JWKS, like a real AWS account's.
  setup %{public_jwk: public_jwk, ec: ec} do
    start_jwks_auth(default_config(), [public_jwk, ec.public_jwk])
    :ok
  end

  describe "verify/2" do
    test "accepts a token matching trusted issuer, allowed sub and expected aud", %{pem: pem} do
      token = sign_token(pem, default_claims())

      assert {:ok, claims} = JWKS.verify(token, default_config())
      assert claims["sub"] == sub()
    end

    test "rejects an untrusted issuer", %{pem: pem} do
      token = sign_token(pem, %{default_claims() | "iss" => "https://not-trusted.example"})

      assert {:error, :untrusted_issuer} = JWKS.verify(token, default_config())
    end

    test "rejects a subject not in the allow-list", %{pem: pem} do
      token =
        sign_token(pem, %{default_claims() | "sub" => "arn:aws:iam::123456789012:role/other"})

      assert {:error, :subject_not_allowed} = JWKS.verify(token, default_config())
    end

    test "rejects a mismatched audience", %{pem: pem} do
      token = sign_token(pem, %{default_claims() | "aud" => "someone-else"})

      assert {:error, :unexpected_audience} = JWKS.verify(token, default_config())
    end

    test "rejects any token when expected_aud isn't configured", %{pem: pem} do
      token = sign_token(pem, default_claims())
      config = %{default_config() | expected_aud: nil}

      assert {:error, :expected_aud_not_configured} = JWKS.verify(token, config)
    end

    test "rejects an expired token", %{pem: pem} do
      exp = Joken.current_time() - 10
      token = sign_token(pem, %{default_claims() | "exp" => exp})

      assert {:error, [message: "Invalid token", claim: "exp", claim_val: ^exp]} =
               JWKS.verify(token, default_config())
    end

    test "a kid absent from the fetched JWKS fails closed", %{pem: pem} do
      token = sign_token(pem, default_claims(), kid: "not-in-jwks")

      assert {:error, :kid_does_not_match} = JWKS.verify(token, default_config())
    end

    test "a token without a kid header fails closed", %{pem: pem} do
      signer = Joken.Signer.create("RS256", %{"pem" => pem})
      token = JWKS.Token.generate_and_sign!(default_claims(), signer)

      assert {:error, :no_kid_in_token_header} = JWKS.verify(token, default_config())
    end

    test "accepts an ES384 token signed by the account's EC key", %{ec: ec} do
      token = sign_token(ec.pem, default_claims(), alg: "ES384", kid: ec_kid())

      assert {:ok, claims} = JWKS.verify(token, default_config())
      assert claims["sub"] == sub()
    end

    test "a token signed with a different key than the JWKS entry for its kid is rejected" do
      %{pem: other_pem} = generate_rsa_keypair()
      token = sign_token(other_pem, default_claims())

      assert {:error, :signature_error} = JWKS.verify(token, default_config())
    end
  end
end
