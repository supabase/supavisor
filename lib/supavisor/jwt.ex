defmodule Supavisor.Jwt do
  @moduledoc """
  Parse JWT and verify claims
  """
  require Logger

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

  @hs_algorithms ["HS256", "HS384", "HS512"]

  @spec authorize(String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def authorize(token, secret) when is_binary(token) do
    token
    |> clean_token()
    |> verify(secret)
  end

  defp clean_token(token) do
    Regex.replace(~r/\s|\n/, URI.decode(token), "")
  end

  def authorize_conn(token, secret) do
    case authorize(token, secret) do
      {:ok, claims} ->
        required = MapSet.new(["role", "exp"])
        claims_keys = Map.keys(claims) |> MapSet.new()

        if MapSet.subset?(required, claims_keys) do
          {:ok, claims}
        else
          {:error, "Fields `role` and `exp` are required in JWT"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Authorizes a token against either a shared HMAC secret or, if configured,
  AWS-identity JWKS verification (`Supavisor.Jwt.AwsIdentity`) — dispatching
  on the token's JWS header `alg` rather than trying one then the other.
  `HS256/384/512` always goes through the existing HMAC path unchanged;
  anything else only succeeds if `jwks_config` is set, so this is a no-op
  behavior change wherever JWKS isn't configured.
  """
  @spec authorize_dual(String.t(), String.t(), Supavisor.Jwt.AwsIdentity.config() | nil) ::
          {:ok, map(), :hmac | :jwks} | {:error, any()}
  def authorize_dual(token, hmac_secret, jwks_config) when is_binary(token) do
    token = clean_token(token)

    with {:ok, alg} <- peek_alg(token) do
      dispatch_authorize(token, alg, hmac_secret, jwks_config)
    end
  end

  def authorize_dual(_token, _hmac_secret, _jwks_config), do: {:error, :token_not_a_string}

  defp dispatch_authorize(token, alg, hmac_secret, _jwks_config) when alg in @hs_algorithms do
    with {:ok, claims} <- verify(token, hmac_secret), do: {:ok, claims, :hmac}
  end

  defp dispatch_authorize(token, _alg, _hmac_secret, jwks_config) when is_map(jwks_config) do
    with {:ok, claims} <- Supavisor.Jwt.AwsIdentity.verify(token, jwks_config),
         do: {:ok, claims, :jwks}
  end

  defp dispatch_authorize(_token, _alg, _hmac_secret, _jwks_config),
    do: {:error, :jwks_not_configured}

  defp peek_alg(token) do
    with {:ok, header} <- check_header_format(token) do
      case header["alg"] do
        alg when is_binary(alg) -> {:ok, alg}
        _ -> {:error, :missing_alg}
      end
    end
  end

  @spec verify(String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def verify(token, secret) when is_binary(token) do
    with {:ok, _claims} <- check_claims_format(token),
         {:ok, header} <- check_header_format(token),
         {:ok, signer} <- generate_signer(header, secret) do
      Token.verify_and_validate(token, signer)
    end
  end

  def verify(_token, _secret), do: {:error, :token_not_a_string}

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
