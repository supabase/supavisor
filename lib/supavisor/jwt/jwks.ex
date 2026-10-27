defmodule Supavisor.JWT.JWKS do
  @moduledoc """
  Verifies JWTs minted by AWS STS's `GetWebIdentityToken` (RS256/ES384,
  verifiable via the issuing AWS account's JWKS at
  `{issuer}/.well-known/jwks.json`) — an additional, equally-trusted auth
  mechanism alongside the shared-secret path (`Supavisor.JWT.SharedSecret`),
  dispatched to by `Supavisor.JWT`.

  Joken/`JokenJwks` (see `Token` below) verifies the signature and validates
  `exp`, `nbf` and `iss`/`sub`/`aud` against a caller-supplied config.
  """

  defmodule Token do
    @moduledoc false
    use Joken.Config

    add_hook(JokenJwks, strategy: Supavisor.JWT.JWKS.Strategy)
    add_hook(Joken.Hooks.RequiredClaims, ["exp", "iss", "sub", "aud"])

    # The validators get the `t:Supavisor.JWT.JWKS.config/0` passed as Joken's `context`.
    @impl true
    def token_config do
      %{}
      |> add_claim("exp", nil, &(is_number(&1) and &1 > current_time()))
      |> add_claim("nbf", nil, &(is_number(&1) and current_time() >= &1))
      |> add_claim("iss", nil, fn iss, _claims, config -> iss == config.trusted_issuer end)
      |> add_claim("sub", nil, fn sub, _claims, config -> sub in config.allowed_subs end)
      # RFC 7519 §4.1.3: `aud` is a string or an array of strings
      |> add_claim("aud", nil, fn aud, _claims, config ->
        is_binary(config.expected_aud) and config.expected_aud in List.wrap(aud)
      end)
    end
  end

  @type config :: %{
          trusted_issuer: String.t(),
          allowed_subs: [String.t()],
          expected_aud: String.t()
        }

  # A failed claim comes back as Joken's `[message: _, claim: key, claim_val: _]`;
  # `Supavisor.JWT` logs and tags it.
  @spec verify(String.t(), config()) :: {:ok, map()} | {:error, term()}
  def verify(token, %{} = config) when is_binary(token) do
    Token.verify_and_validate(token, Token.__default_signer__(), config)
  end
end
