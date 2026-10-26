defmodule Supavisor.JWKSHelper do
  @moduledoc """
  Test helpers for the JWKS path of `Supavisor.JWT`.

  Tokens are signed with a throwaway private key the test holds; the matching
  public key is served as the issuer's JWKS through `Tesla.Mock`, and the real
  `Supavisor.JWT.JWKS.Strategy` fetches and caches it, so verification goes
  through the actual `JokenJwks` machinery. Signing needs only the private key,
  verification only the public JWKS entry.

  The RSA public key has no `"alg"`, like AWS's real JWKS (see
  `Supavisor.JWT.JWKS.AlgFixup`); the EC key carries `"alg": "ES384"`, also like AWS.

  `start_jwks_auth/2` starts a named singleton and mutates global state
  (`:api_jwks_config`, `Tesla.Mock`), so tests using it must be `async: false`.
  """

  import ExUnit.Callbacks, only: [on_exit: 1, start_supervised!: 1]

  alias Supavisor.JWT.JWKS

  @kid "test-kid"
  @ec_kid "test-ec-kid"
  @issuer "https://issuer.example.tokens.sts.global.api.aws"
  @sub "arn:aws:iam::123456789012:role/supavisor-api"
  @aud "supavisor-api"

  def issuer, do: @issuer
  def sub, do: @sub
  def aud, do: @aud
  def kid, do: @kid
  def ec_kid, do: @ec_kid

  @doc "A fresh RSA keypair: `%{pem: private_pem, public_jwk: jwk_without_alg}`."
  def generate_rsa_keypair do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    {_, pem} = JOSE.JWK.to_pem(jwk)
    {_, public_jwk} = JOSE.JWK.to_public_map(jwk)

    %{pem: pem, public_jwk: Map.put(public_jwk, "kid", @kid)}
  end

  @doc "A fresh P-384 keypair: `%{pem: private_pem, public_jwk: jwk_with_alg}`."
  def generate_ec_keypair do
    jwk = JOSE.JWK.generate_key({:ec, :secp384r1})
    {_, pem} = JOSE.JWK.to_pem(jwk)
    {_, public_jwk} = JOSE.JWK.to_public_map(jwk)

    %{pem: pem, public_jwk: Map.merge(public_jwk, %{"kid" => @ec_kid, "alg" => "ES384"})}
  end

  def default_config do
    %{trusted_issuer: @issuer, allowed_subs: [@sub], expected_aud: @aud}
  end

  def default_claims do
    %{
      "iss" => @issuer,
      "sub" => @sub,
      "aud" => @aud,
      "exp" => Joken.current_time() + 300
    }
  end

  @doc """
  Signs `claims` with `pem`. `opts`: `:alg` (default `"RS256"`), `:kid` (default
  the RSA test kid).
  """
  def sign_token(pem, claims, opts \\ []) do
    alg = Keyword.get(opts, :alg, "RS256")
    kid = Keyword.get(opts, :kid, @kid)
    signer = Joken.Signer.create(alg, %{"pem" => pem}, %{"kid" => kid})

    JWKS.Token.generate_and_sign!(claims, signer)
  end

  @doc "Sets `:api_jwks_config` for the current test, restoring the previous value on exit."
  def put_jwks_config(config) do
    previous = Application.get_env(:supavisor, :api_jwks_config)
    Application.put_env(:supavisor, :api_jwks_config, config)
    on_exit(fn -> Application.put_env(:supavisor, :api_jwks_config, previous) end)
  end

  @doc """
  Serves `public_jwk` (one JWK or a list) as the issuer's JWKS, sets `config` as
  `:api_jwks_config` and starts the real `Supavisor.JWT.JWKS.Strategy` (it reads
  the issuer from that config). Restores the previous config on exit.
  """
  def start_jwks_auth(config, public_jwks) do
    put_jwks_config(config)

    keys = List.wrap(public_jwks)

    # Raw JSON string + a real content-type header, not a pre-decoded map: a mock
    # handing back a decoded map would mask bugs in how `http_middlewares` interacts
    # with Tesla's JSON middleware (see `Supavisor.JWT.JWKS.AlgFixup`).
    Tesla.Mock.mock_global(fn
      %{method: :get, url: @issuer <> "/.well-known/jwks.json"} ->
        %Tesla.Env{
          status: 200,
          body: JSON.encode!(%{"keys" => keys}),
          headers: [{"content-type", "application/json"}]
        }
    end)

    start_supervised!({JWKS.Strategy, [first_fetch_sync: true, http_adapter: Tesla.Mock]})
  end
end
