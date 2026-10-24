defmodule Supavisor.Jwt do
  @moduledoc """
  Parse JWT and verify claims
  """
  require Logger

  alias Supavisor.Jwt.AwsIdentity

  @hs_algorithms ["HS256", "HS384", "HS512"]

  ### API

  defmodule Token do
    @moduledoc false
    use Joken.Config

    def default_signer(secret),
      do: Joken.Signer.create("HS256", secret)

    def gen!(claims \\ %{}, secret)

    def gen!(claims, secret) when is_binary(secret),
      do: gen!(claims, default_signer(secret))

    def gen!(claims, signer) do
      default = %{"exp" => Joken.current_time() + 3600}

      generate_and_sign!(Map.merge(default, claims), signer)
    end

    @impl true
    def token_config do
      Application.fetch_env!(:supavisor, :jwt_claim_validators)
      |> Enum.reduce(%{}, fn {claim_key, expected_val}, claims ->
        add_claim_validator(claims, claim_key, expected_val)
      end)
      |> add_claim_validator("exp")
    end

    defp add_claim_validator(claims, "exp") do
      add_claim(claims, "exp", nil, &(&1 > current_time()))
    end

    defp add_claim_validator(claims, claim_key, expected_val) do
      add_claim(claims, claim_key, nil, &(&1 == expected_val))
    end
  end

  @doc """
  Strips whitespace and URI-decodes a raw bearer token

   Not idempotent (`URI.decode/1` runs on every call), so callers should clean exactly once.
  """
  @spec clean_token(String.t()) :: String.t()
  def clean_token(token) do
    Regex.replace(~r/\s|\n/, URI.decode(token), "")
  end

  @doc """
  Verifies a JWT using the given HMAC secret.

  Returns `{:ok, claims}` if the token is valid, or `{:error, reason}` otherwise.
  """
  @spec verify(String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def verify(token, secret) when is_binary(token) do
    with {:ok, _claims} <- check_claims_format(token),
         {:ok, header} <- check_header_format(token),
         {:ok, signer} <- generate_signer(header, secret) do
      Token.verify_and_validate(token, signer)
    end
  end

  def verify(_token, _secret), do: {:error, :token_not_a_string}

  @doc """
  Authorizes a token against either a shared HMAC secret or, if configured,
  AWS-identity JWKS verification (`Supavisor.Jwt.AwsIdentity`) — dispatching
  on the token's JWS header `alg`.

  `HS256/384/512` always goes through the existing HMAC path unchanged;
  anything else only succeeds if `jwks_config` is set, so this is a no-op
  behavior change wherever JWKS isn't configured.

  Expects an already-cleaned token (see `clean_token/1`). Both outcomes carry
  the method that ran, `:unknown` if the token has no parsable header `alg`.
  """
  @spec authorize_dual(String.t(), String.t(), AwsIdentity.config() | nil) ::
          {:ok, :hmac | :jwks, map()} | {:error, :hmac | :jwks | :unknown, any()}
  def authorize_dual(token, hmac_secret, jwks_config) when is_binary(token) do
    case peek_alg(token) do
      {:ok, alg} -> dispatch_authorize(token, alg, hmac_secret, jwks_config)
      {:error, reason} -> {:error, :unknown, reason}
    end
  end

  def authorize_dual(_token, _hmac_secret, _jwks_config),
    do: {:error, :unknown, :token_not_a_string}

  ### HELPERS

  defp dispatch_authorize(token, alg, hmac_secret, _jwks_config) when alg in @hs_algorithms do
    case verify(token, hmac_secret) do
      {:ok, claims} -> {:ok, :hmac, claims}
      {:error, reason} -> {:error, :hmac, reason}
    end
  end

  defp dispatch_authorize(token, _alg, _hmac_secret, jwks_config) when is_map(jwks_config) do
    case AwsIdentity.verify(token, jwks_config) do
      {:ok, claims} -> {:ok, :jwks, claims}
      {:error, reason} -> {:error, :jwks, reason}
    end
  end

  defp dispatch_authorize(_token, _alg, _hmac_secret, _jwks_config),
    do: {:error, :jwks, :jwks_not_configured}

  defp peek_alg(token) do
    with {:ok, header} <- check_header_format(token) do
      case header["alg"] do
        alg when is_binary(alg) -> {:ok, alg}
        _ -> {:error, :missing_alg}
      end
    end
  end

  defp check_header_format(token) do
    case Joken.peek_header(token) do
      {:ok, header} when is_map(header) -> {:ok, header}
      _error -> {:error, :expected_header_map}
    end
  end

  defp check_claims_format(token) do
    case Joken.peek_claims(token) do
      {:ok, claims} when is_map(claims) -> {:ok, claims}
      _error -> {:error, :expected_claims_map}
    end
  end

  defp generate_signer(%{"typ" => "JWT", "alg" => alg}, jwt_secret) when alg in @hs_algorithms do
    {:ok, Joken.Signer.create(alg, jwt_secret)}
  end

  defp generate_signer(_header, _secret), do: {:error, :error_generating_signer}
end
