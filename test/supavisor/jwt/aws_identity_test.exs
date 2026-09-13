defmodule Supavisor.Jwt.AwsIdentityTest do
  # Starts the real, named `Supavisor.Jwt.JwksStrategy` singleton and mutates
  # global `Application` env (`:api_jwks_config`) plus the global Tesla.Mock —
  # must not run concurrently with other tests touching the same state.
  use ExUnit.Case, async: false

  alias Supavisor.Jwt.AwsIdentity

  @kid "test-kid"
  @issuer "https://issuer.example.tokens.sts.global.api.aws"
  @sub "arn:aws:iam::123456789012:role/supavisor-api"
  @aud "supavisor-api"

  setup_all do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    {_, pem} = JOSE.JWK.to_pem(jwk)
    {_, public_jwk} = JOSE.JWK.to_public_map(jwk)

    # No "alg" — matches AWS's real outbound-identity-federation JWKS shape
    # for RSA keys (see Supavisor.Jwt.JwksAlgFixup). Exercises the fixup.
    %{pem: pem, public_jwk: Map.merge(public_jwk, %{"kid" => @kid})}
  end

  # `Supavisor.Jwt.JwksStrategy` (the real, single-issuer module — see its
  # moduledoc for why there's exactly one) is hardcoded into
  # `AwsIdentity.Token`'s `add_hook/2` at compile time, so every test here
  # goes through the actual JokenJwks fetch/cache machinery against a
  # `Tesla.Mock`-served JWKS, rather than a stand-in strategy module.
  setup %{public_jwk: public_jwk} do
    Application.put_env(:supavisor, :api_jwks_config, default_config())

    # Raw JSON string body + a real content-type header — matching the
    # actual wire format `Tesla.Mock` would otherwise skip past (it can hand
    # back an already-decoded map directly, which masks bugs in how
    # `http_middlewares` interacts with Tesla's JSON-decoding middleware;
    # see `Supavisor.Jwt.JwksAlgFixup`'s moduledoc).
    Tesla.Mock.mock_global(fn
      %{method: :get, url: @issuer <> "/.well-known/jwks.json"} ->
        %Tesla.Env{
          status: 200,
          body: JSON.encode!(%{"keys" => [public_jwk]}),
          headers: [{"content-type", "application/json"}]
        }
    end)

    {:ok, _pid} =
      start_supervised(
        {Supavisor.Jwt.JwksStrategy, [first_fetch_sync: true, http_adapter: Tesla.Mock]}
      )

    on_exit(fn -> Application.put_env(:supavisor, :api_jwks_config, nil) end)

    :ok
  end

  defp sign(pem, claims, kid \\ @kid) do
    signer = Joken.Signer.create("RS256", %{"pem" => pem}, %{"kid" => kid})
    AwsIdentity.Token.generate_and_sign!(claims, signer)
  end

  defp default_config do
    %{trusted_issuer: @issuer, allowed_subs: [@sub], expected_aud: @aud}
  end

  defp default_claims do
    %{
      "iss" => @issuer,
      "sub" => @sub,
      "aud" => @aud,
      "exp" => Joken.current_time() + 300
    }
  end

  describe "verify/2" do
    test "accepts a token matching trusted issuer, allowed sub and expected aud", %{pem: pem} do
      token = sign(pem, default_claims())

      assert {:ok, claims} = AwsIdentity.verify(token, default_config())
      assert claims["sub"] == @sub
    end

    test "rejects an untrusted issuer", %{pem: pem} do
      token = sign(pem, %{default_claims() | "iss" => "https://not-trusted.example"})

      assert {:error, :untrusted_issuer} = AwsIdentity.verify(token, default_config())
    end

    test "rejects a subject not in the allow-list", %{pem: pem} do
      token = sign(pem, %{default_claims() | "sub" => "arn:aws:iam::123456789012:role/other"})

      assert {:error, :subject_not_allowed} = AwsIdentity.verify(token, default_config())
    end

    test "rejects a mismatched audience", %{pem: pem} do
      token = sign(pem, %{default_claims() | "aud" => "someone-else"})

      assert {:error, :unexpected_audience} = AwsIdentity.verify(token, default_config())
    end

    test "rejects any token when expected_aud isn't configured", %{pem: pem} do
      token = sign(pem, default_claims())
      config = %{default_config() | expected_aud: nil}

      assert {:error, :expected_aud_not_configured} = AwsIdentity.verify(token, config)
    end

    test "rejects an expired token", %{pem: pem} do
      token = sign(pem, %{default_claims() | "exp" => Joken.current_time() - 10})

      assert {:error, _reason} = AwsIdentity.verify(token, default_config())
    end

    test "a kid absent from the fetched JWKS fails closed", %{pem: pem} do
      token = sign(pem, default_claims(), "not-in-jwks")

      assert {:error, _reason} = AwsIdentity.verify(token, default_config())
    end
  end
end
