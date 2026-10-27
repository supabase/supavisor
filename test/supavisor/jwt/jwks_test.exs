defmodule Supavisor.JWT.JWKSTest do
  # Starts the real, named `Supavisor.JWT.JWKS.Strategy` singleton and mutates
  # global `Application` env (`:api_jwks_config`) plus the global Tesla.Mock —
  # must not run concurrently with other tests touching the same state.
  use ExUnit.Case, async: false

  import Supavisor.Support.JWKSHelper,
    only: [
      aud: 0,
      default_claims: 0,
      default_config: 0,
      ec_kid: 0,
      generate_ec_keypair: 0,
      generate_rsa_keypair: 0,
      sign_token: 2,
      sign_token: 3,
      start_jwks_auth: 2,
      sub: 0
    ]

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

      assert {:error,
              [message: "Invalid token", claim: "iss", claim_val: "https://not-trusted.example"]} =
               JWKS.verify(token, default_config())
    end

    test "rejects a subject not in the allow-list", %{pem: pem} do
      other = "arn:aws:iam::123456789012:role/other"
      token = sign_token(pem, %{default_claims() | "sub" => other})

      assert {:error, [message: "Invalid token", claim: "sub", claim_val: ^other]} =
               JWKS.verify(token, default_config())
    end

    test "rejects a mismatched audience", %{pem: pem} do
      token = sign_token(pem, %{default_claims() | "aud" => "someone-else"})

      assert {:error, [message: "Invalid token", claim: "aud", claim_val: "someone-else"]} =
               JWKS.verify(token, default_config())
    end

    test "accepts an array-valued aud that contains the expected audience", %{pem: pem} do
      token = sign_token(pem, %{default_claims() | "aud" => [aud()]})
      assert {:ok, %{"aud" => [_]}} = JWKS.verify(token, default_config())

      token = sign_token(pem, %{default_claims() | "aud" => ["someone-else", aud()]})
      assert {:ok, _claims} = JWKS.verify(token, default_config())
    end

    test "rejects an array-valued aud without the expected audience", %{pem: pem} do
      for bad <- [["someone-else"], ["someone-else", "another"], []] do
        token = sign_token(pem, %{default_claims() | "aud" => bad})

        assert {:error, [message: "Invalid token", claim: "aud", claim_val: ^bad]} =
                 JWKS.verify(token, default_config())
      end
    end

    test "rejects an aud that is neither a string nor a list of strings", %{pem: pem} do
      bad = %{"x" => aud()}
      token = sign_token(pem, %{default_claims() | "aud" => bad})

      assert {:error, [message: "Invalid token", claim: "aud", claim_val: ^bad]} =
               JWKS.verify(token, default_config())
    end

    test "rejects any token when expected_aud isn't configured", %{pem: pem} do
      config = %{default_config() | expected_aud: nil}

      for aud <- [aud(), [aud()], [nil]] do
        token = sign_token(pem, %{default_claims() | "aud" => aud})

        assert {:error, [message: "Invalid token", claim: "aud", claim_val: ^aud]} =
                 JWKS.verify(token, config)
      end
    end

    for claim <- ["exp", "iss", "sub", "aud"] do
      test "rejects a token without #{claim}, which Joken alone would not validate",
           %{pem: pem} do
        token = sign_token(pem, Map.delete(default_claims(), unquote(claim)))

        assert {:error, [message: "Invalid token", missing_claims: [unquote(claim)]]} =
                 JWKS.verify(token, default_config())
      end
    end

    test "rejects a non-numeric exp or nbf", %{pem: pem} do
      for claim <- ["exp", "nbf"] do
        token = sign_token(pem, Map.put(default_claims(), claim, "9999999999"))

        assert {:error, [message: "Invalid token", claim: ^claim, claim_val: "9999999999"]} =
                 JWKS.verify(token, default_config())
      end
    end

    test "rejects an expired token", %{pem: pem} do
      exp = Joken.current_time() - 10
      token = sign_token(pem, %{default_claims() | "exp" => exp})

      assert {:error, [message: "Invalid token", claim: "exp", claim_val: ^exp]} =
               JWKS.verify(token, default_config())
    end

    test "rejects a token that is not valid yet (nbf in the future)", %{pem: pem} do
      nbf = Joken.current_time() + 3_600
      token = sign_token(pem, Map.put(default_claims(), "nbf", nbf))

      assert {:error, [message: "Invalid token", claim: "nbf", claim_val: ^nbf]} =
               JWKS.verify(token, default_config())
    end

    test "accepts a token whose nbf has passed", %{pem: pem} do
      token = sign_token(pem, Map.put(default_claims(), "nbf", Joken.current_time() - 60))

      assert {:ok, claims} = JWKS.verify(token, default_config())
      assert claims["sub"] == sub()
    end

    test "accepts a token without nbf", %{pem: pem} do
      claims = default_claims()
      refute Map.has_key?(claims, "nbf")

      assert {:ok, _claims} = JWKS.verify(sign_token(pem, claims), default_config())
    end

    test "does not enforce iat or jti", %{pem: pem} do
      claims = Map.merge(default_claims(), %{"iat" => Joken.current_time() + 3_600, "jti" => "x"})

      assert {:ok, _claims} = JWKS.verify(sign_token(pem, claims), default_config())
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
