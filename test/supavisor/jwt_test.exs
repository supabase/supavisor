defmodule Supavisor.JWTTest do
  # Starts the real, named `Supavisor.JWT.JWKS.Strategy` in the JWKS tests and
  # mutates global `Application` env and telemetry handlers — not concurrent.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn

  import Supavisor.Support.JWKSHelper,
    only: [
      default_claims: 0,
      default_config: 0,
      ec_kid: 0,
      generate_ec_keypair: 0,
      generate_rsa_keypair: 0,
      kid: 0,
      sign_token: 2,
      sign_token: 3,
      start_jwks_auth: 2,
      sub: 0
    ]

  import Supavisor.Support.JWTAuthHelper, only: [attach_jwt_auth_telemetry_handler: 0]

  alias Supavisor.JWT
  alias Supavisor.JWT.SharedSecret.Token

  # Own app-env keys, so the test never touches the real :api_* / :metrics_* config.
  @secret "my_secret_key"
  @opts [pipeline: :api, secret: :jwt_test_secret, blocklist: :jwt_test_blocklist]
  @opts_jwks @opts ++ [jwks: :api_jwks_config]

  setup_all do
    generate_rsa_keypair()
  end

  setup do
    Application.put_env(:supavisor, :jwt_test_secret, @secret)
    Application.put_env(:supavisor, :jwt_test_blocklist, [])

    on_exit(fn ->
      Application.delete_env(:supavisor, :jwt_test_secret)
      Application.delete_env(:supavisor, :jwt_test_blocklist)
    end)

    %{ref: attach_jwt_auth_telemetry_handler()}
  end

  # These steps run before the token's `alg` is read, so they behave the same whichever
  # verifier the token is dispatched to; HMAC tokens are enough, except where noted.
  describe "bearer token handling" do
    test "returns the claims of a valid token" do
      assert {:ok, %{"role" => "test"}} = JWT.authorize(conn_with(hmac_token()), @opts)
    end

    test "rejects a missing authorization header", %{ref: ref} do
      assert {:error, :invalid_authorization_header} = JWT.authorize(base_conn(), @opts)
      assert_rejected(ref, :unknown, :api, :invalid_authorization_header)
    end

    test "rejects a non-Bearer authorization header", %{ref: ref} do
      conn = put_req_header(base_conn(), "authorization", "Basic dXNlcjpwYXNz")

      assert {:error, :invalid_authorization_header} = JWT.authorize(conn, @opts)
      assert_rejected(ref, :unknown, :api, :invalid_authorization_header)
    end

    test "rejects a repeated authorization header", %{ref: ref} do
      bearer = "Bearer " <> hmac_token()
      conn = %{base_conn() | req_headers: [{"authorization", bearer}, {"authorization", bearer}]}

      assert {:error, :invalid_authorization_header} = JWT.authorize(conn, @opts)
      assert_rejected(ref, :unknown, :api, :invalid_authorization_header)
    end

    test "blocklists a JWKS-style token too, before its alg selects a verifier", %{ref: ref} do
      token = unsigned_token(%{"alg" => "RS256", "typ" => "JWT", "kid" => kid()})
      Application.put_env(:supavisor, :jwt_test_blocklist, [token])

      assert {:error, :token_blocklisted} = JWT.authorize(conn_with(token), @opts)
      assert_rejected(ref, :unknown, :api, :token_blocklisted)
    end

    test "cleans the token: percent-encoding and whitespace are stripped" do
      token = hmac_token()
      encoded = String.replace(token, ".", "%2E")
      {head, tail} = String.split_at(token, 10)

      assert {:ok, _claims} = JWT.authorize(conn_with(encoded), @opts)
      assert {:ok, _claims} = JWT.authorize(conn_with(head <> " \n" <> tail), @opts)
    end

    test "rejects a blocklisted token, also when it is sent encoded", %{ref: ref} do
      token = hmac_token()
      Application.put_env(:supavisor, :jwt_test_blocklist, [token])

      assert {:error, :token_blocklisted} = JWT.authorize(conn_with(token), @opts)
      assert_rejected(ref, :unknown, :api, :token_blocklisted)

      encoded = String.replace(token, ".", "%2E")
      assert {:error, :token_blocklisted} = JWT.authorize(conn_with(encoded), @opts)
    end
  end

  describe "telemetry and logging" do
    test "emits ok with the method and the pipeline", %{ref: ref} do
      assert {:ok, _claims} = JWT.authorize(conn_with(hmac_token()), @opts)
      assert_received {^ref, [:supavisor, :jwt_auth, :ok], %{count: 1}, meta}
      assert meta == %{method: :hmac, pipeline: :api}

      opts = Keyword.put(@opts, :pipeline, :metrics)
      assert {:ok, _claims} = JWT.authorize(conn_with(hmac_token()), opts)
      assert_received {^ref, [:supavisor, :jwt_auth, :ok], %{count: 1}, %{pipeline: :metrics}}

      refute_received {^ref, [:supavisor, :jwt_auth, :rejected], _, _}
    end

    test "emits rejected with a reason tag", %{ref: ref} do
      token = Token.gen!(%{"role" => "test"}, "another_secret")

      assert {:error, :signature_error} = JWT.authorize(conn_with(token), @opts)
      assert_rejected(ref, :hmac, :api, :signature_error)
      refute_received {^ref, [:supavisor, :jwt_auth, :ok], _, _}
    end

    test "tags an expired token :token_expired and logs exp vs now in ISO8601", %{ref: ref} do
      exp = Joken.current_time() - 60
      token = Token.gen!(%{"role" => "test", "exp" => exp}, @secret)
      expected_exp = exp |> DateTime.from_unix!() |> DateTime.to_iso8601()

      log =
        capture_log(fn ->
          assert {:error, [message: "Invalid token", claim: "exp", claim_val: ^exp]} =
                   JWT.authorize(conn_with(token), @opts)
        end)

      assert_rejected(ref, :hmac, :api, :token_expired)
      assert log =~ "check_auth: rejected api GET /api/tenants/x"
      assert log =~ "token_expired"
      assert log =~ ~s(exp: "#{expected_exp}")
      assert log =~ ~r/now: "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"/
    end

    test "never logs the token" do
      token = hmac_token()

      log =
        capture_log(fn ->
          JWT.authorize(conn_with(token <> "x"), @opts)
        end)

      assert log =~ "rejected"
      refute log =~ token
    end
  end

  describe "dispatching on the token's alg without JWKS configured" do
    test "HS256, HS384 and HS512 tokens go to the shared-secret verifier", %{ref: ref} do
      for alg <- ["HS256", "HS384", "HS512"] do
        token = Token.gen!(%{"role" => "test"}, Joken.Signer.create(alg, @secret))

        assert {:ok, %{"role" => "test"}} = JWT.authorize(conn_with(token), @opts)
        assert_received {^ref, [:supavisor, :jwt_auth, :ok], _, %{method: :hmac}}
      end
    end

    test "a non-HS alg is rejected as jwks_not_configured", %{ref: ref} do
      token = unsigned_token(%{"alg" => "RS256", "typ" => "JWT", "kid" => kid()})

      assert {:error, :jwks_not_configured} = JWT.authorize(conn_with(token), @opts)
      assert_rejected(ref, :jwks, :api, :jwks_not_configured)
    end

    test "a non-HS alg is rejected without a :jwks verification path too (e.g. /metrics)", %{
      ref: ref
    } do
      token = unsigned_token(%{"alg" => "ES384", "typ" => "JWT"})
      opts = Keyword.put(@opts, :pipeline, :metrics)

      assert {:error, :jwks_not_configured} = JWT.authorize(conn_with(token), opts)
      assert_rejected(ref, :jwks, :metrics, :jwks_not_configured)
    end

    test "garbage and a header without alg have an :unknown method", %{ref: ref} do
      assert {:error, :expected_header_map} = JWT.authorize(conn_with("not-a-jwt"), @opts)
      assert_rejected(ref, :unknown, :api, :expected_header_map)

      no_alg = unsigned_token(%{"typ" => "JWT"})
      assert {:error, :missing_alg} = JWT.authorize(conn_with(no_alg), @opts)
      assert_rejected(ref, :unknown, :api, :missing_alg)
    end
  end

  describe "payload check shared by every verifier" do
    test "a non-map payload is rejected before dispatch, tagged with the claimed method",
         %{ref: ref} do
      hs = bad_payload_token(%{"alg" => "HS256", "typ" => "JWT"})
      assert {:error, :expected_claims_map} = JWT.authorize(conn_with(hs), @opts)
      assert_rejected(ref, :hmac, :api, :expected_claims_map)

      rs = bad_payload_token(%{"alg" => "RS256", "typ" => "JWT", "kid" => kid()})
      assert {:error, :expected_claims_map} = JWT.authorize(conn_with(rs), @opts)
      assert_rejected(ref, :jwks, :api, :expected_claims_map)
    end
  end

  describe "dispatching on the token's alg with JWKS configured" do
    setup %{public_jwk: public_jwk} do
      ec = generate_ec_keypair()
      start_jwks_auth(default_config(), [public_jwk, ec.public_jwk])
      %{ec: ec}
    end

    test "HS tokens still go to the shared-secret verifier", %{ref: ref} do
      assert {:ok, %{"role" => "test"}} = JWT.authorize(conn_with(hmac_token()), @opts_jwks)
      assert_received {^ref, [:supavisor, :jwt_auth, :ok], _, %{method: :hmac}}
    end

    test "an RS256 token goes to the JWKS verifier", %{ref: ref, pem: pem} do
      token = sign_token(pem, default_claims())

      assert {:ok, claims} = JWT.authorize(conn_with(token), @opts_jwks)
      assert claims["sub"] == sub()
      assert_received {^ref, [:supavisor, :jwt_auth, :ok], _, %{method: :jwks, pipeline: :api}}
    end

    test "an ES384 token goes to the JWKS verifier", %{ref: ref, ec: ec} do
      token = sign_token(ec.pem, default_claims(), alg: "ES384", kid: ec_kid())

      assert {:ok, _claims} = JWT.authorize(conn_with(token), @opts_jwks)
      assert_received {^ref, [:supavisor, :jwt_auth, :ok], _, %{method: :jwks}}
    end

    test "JWKS verification failures are tagged :jwks", %{ref: ref, pem: pem} do
      wrong_sub = sign_token(pem, %{default_claims() | "sub" => "arn:aws:iam::1:role/other"})
      other = "arn:aws:iam::1:role/other"

      assert {:error, [message: "Invalid token", claim: "sub", claim_val: ^other]} =
               JWT.authorize(conn_with(wrong_sub), @opts_jwks)

      assert_rejected(ref, :jwks, :api, :subject_not_allowed)

      exp = Joken.current_time() - 60
      expired = sign_token(pem, %{default_claims() | "exp" => exp})

      assert {:error, [message: "Invalid token", claim: "exp", claim_val: ^exp]} =
               JWT.authorize(conn_with(expired), @opts_jwks)

      assert_rejected(ref, :jwks, :api, :token_expired)
    end

    test "logs the claim and the offending value of a rejected iss, sub or aud", %{pem: pem} do
      for {claim, value, tag} <- [
            {"iss", "https://not-trusted.example", :untrusted_issuer},
            {"sub", "arn:aws:iam::1:role/other", :subject_not_allowed},
            {"aud", ["someone-else"], :unexpected_audience}
          ] do
        token = sign_token(pem, Map.put(default_claims(), claim, value))

        log =
          capture_log(fn ->
            assert {:error, [message: _, claim: ^claim, claim_val: ^value]} =
                     JWT.authorize(conn_with(token), @opts_jwks)
          end)

        assert log =~ "check_auth: rejected api GET /api/tenants/x"
        assert log =~ ~s(claim: "#{claim}")
        assert log =~ "claim_val: #{inspect(value)}"
        refute log =~ token, "#{tag} rejection must not log the token"
      end
    end

    test "logs a not-yet-valid token as :token_not_yet_valid with nbf vs now in ISO8601",
         %{pem: pem} do
      nbf = Joken.current_time() + 3_600
      expected_nbf = nbf |> DateTime.from_unix!() |> DateTime.to_iso8601()
      token = sign_token(pem, Map.put(default_claims(), "nbf", nbf))

      log = capture_log(fn -> JWT.authorize(conn_with(token), @opts_jwks) end)

      assert log =~ "token_not_yet_valid"
      refute log =~ "token_expired"
      assert log =~ ~s(nbf: "#{expected_nbf}")
      assert log =~ ~r/now: "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"/
    end

    test "a token that is not valid yet is rejected with a bounded :token_not_yet_valid tag",
         %{ref: ref, pem: pem} do
      nbf = Joken.current_time() + 3_600
      token = sign_token(pem, Map.put(default_claims(), "nbf", nbf))

      assert {:error, [message: "Invalid token", claim: "nbf", claim_val: ^nbf]} =
               JWT.authorize(conn_with(token), @opts_jwks)

      assert_rejected(ref, :jwks, :api, :token_not_yet_valid)
    end

    test "a token missing a required claim is rejected with the :missing_claims tag",
         %{ref: ref, pem: pem} do
      token = sign_token(pem, Map.delete(default_claims(), "exp"))

      assert {:error, [message: "Invalid token", missing_claims: ["exp"]]} =
               JWT.authorize(conn_with(token), @opts_jwks)

      assert_rejected(ref, :jwks, :api, :missing_claims)
    end

    test "alg none is never accepted", %{ref: ref} do
      token = unsigned_token(%{"alg" => "none", "typ" => "JWT", "kid" => kid()}, default_claims())

      assert {:error, :signature_error} = JWT.authorize(conn_with(token), @opts_jwks)
      assert_received {^ref, [:supavisor, :jwt_auth, :rejected], _, %{method: :jwks}}
      refute_received {^ref, [:supavisor, :jwt_auth, :ok], _, _}
    end

    test "an HS256 token forged with the JWKS public key as secret is rejected (no alg confusion)",
         %{ref: ref, public_jwk: public_jwk} do
      {_, public_pem} = public_jwk |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()
      forged = Token.gen!(default_claims(), public_pem)

      assert {:error, :signature_error} = JWT.authorize(conn_with(forged), @opts_jwks)
      assert_rejected(ref, :hmac, :api, :signature_error)
    end
  end

  defp assert_rejected(ref, method, pipeline, reason) do
    assert_received {^ref, [:supavisor, :jwt_auth, :rejected], %{count: 1}, meta}
    assert meta == %{method: method, pipeline: pipeline, reason: reason}
  end

  defp hmac_token, do: Token.gen!(%{"role" => "test"}, @secret)

  defp base_conn, do: Plug.Test.conn(:get, "/api/tenants/x")

  defp conn_with(token), do: put_req_header(base_conn(), "authorization", "Bearer " <> token)

  defp bad_payload_token(header) do
    encode = &Base.url_encode64(JSON.encode!(&1), padding: false)
    "#{encode.(header)}.#{encode.([1, 2])}.#{Base.url_encode64("sig", padding: false)}"
  end

  # Header/claims are only inspected before verification, so no real signature
  # is needed to test the dispatch decision — just a decodable header.
  defp unsigned_token(header, claims \\ %{}) do
    encode = &Base.url_encode64(JSON.encode!(&1), padding: false)
    "#{encode.(header)}.#{encode.(claims)}.#{Base.url_encode64("fake-signature", padding: false)}"
  end
end
