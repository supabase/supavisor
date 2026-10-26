defmodule Supavisor.JWT.JWKS do
  @moduledoc """
  Verifies JWTs minted by AWS STS's `GetWebIdentityToken` (RS256/ES384,
  verifiable via the issuing AWS account's JWKS at
  `{issuer}/.well-known/jwks.json`) — an additional, equally-trusted auth
  mechanism alongside the shared-secret path (`Supavisor.JWT.SharedSecret`),
  dispatched to by `Supavisor.JWT`.

  Signature + `exp` are verified by Joken/`JokenJwks` (see `Token` below).
  `iss`/`sub`/`aud` are checked explicitly here against a caller-supplied
  config. Nothing here is `/api`-specific — reusable by other pipelines
  (e.g. `/metrics`) with their own config map.
  """

  defmodule Token do
    @moduledoc false
    use Joken.Config

    add_hook(JokenJwks, strategy: Supavisor.JWT.JWKS.Strategy)

    # Only `exp` is enforced here — `iss`/`sub`/`aud` are checked explicitly
    # against runtime config in `verify/2` below, since Joken's default
    # validators only support a single, compile-time-fixed expected value.
    @impl true
    def token_config, do: default_claims(skip: [:iss, :aud, :nbf, :iat, :jti])
  end

  # Only one trusted issuer, deliberately — see `Supavisor.JWT.JWKS.Strategy`'s
  # moduledoc for why (AWS account:issuer is 1:1, and consumers are expected
  # to assume the shared `supavisor-api` role first, so every accepted token
  # comes from this pooler cluster's own account regardless of caller).
  @type config :: %{
          trusted_issuer: String.t(),
          allowed_subs: [String.t()],
          expected_aud: String.t() | nil
        }

  @spec verify(String.t(), config()) :: {:ok, map()} | {:error, atom()}
  def verify(token, %{trusted_issuer: issuer, allowed_subs: subs, expected_aud: aud})
      when is_binary(token) do
    with {:ok, claims} <- Token.verify_and_validate(token),
         {:ok, claims} <- require_claim_equals(claims, "iss", issuer, :untrusted_issuer),
         {:ok, claims} <- require_claim_in(claims, "sub", subs, :subject_not_allowed),
         :ok <- check_aud(claims["aud"], aud) do
      {:ok, claims}
    end
  end

  defp require_claim_equals(claims, key, expected, error) do
    if claims[key] == expected do
      {:ok, claims}
    else
      {:error, error}
    end
  end

  defp require_claim_in(claims, key, allowed, error) do
    if claims[key] in allowed do
      {:ok, claims}
    else
      {:error, error}
    end
  end

  defp check_aud(_claim_aud, nil), do: {:error, :expected_aud_not_configured}

  # RFC 7519 §4.1.3: `aud` is a string or an array of strings
  defp check_aud(claim_aud, expected_aud) do
    if expected_aud in List.wrap(claim_aud) do
      :ok
    else
      {:error, :unexpected_audience}
    end
  end
end
