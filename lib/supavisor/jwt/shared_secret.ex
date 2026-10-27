defmodule Supavisor.JWT.SharedSecret do
  @moduledoc """
  Verifies HMAC-signed (`HS256`/`HS384`/`HS512`) JWTs against a secret shared
  with the caller (`API_JWT_SECRET`, `METRICS_JWT_SECRET`).

  Dispatched to by `Supavisor.JWT` when the token's JWS header `alg` is an HMAC
  algorithm. Signature and claim validation (`exp` plus any configured
  `:jwt_claim_validators`) are done by `Token`.
  """

  # https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2
  @algorithms ["HS256", "HS384", "HS512"]

  @doc false
  def algorithms, do: @algorithms

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
  Verifies `token` against `secret`

  The structural checks every verifier needs (map header with an `alg`, map payload)
  are done once in `Supavisor.JWT`.
  """
  @spec verify(String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def verify(token, secret) when is_binary(token) do
    with {:ok, header} <- peek_header(token),
         {:ok, signer} <- generate_signer(header, secret) do
      Token.verify_and_validate(token, signer)
    end
  end

  def verify(_token, _secret), do: {:error, :token_not_a_string}

  defp peek_header(token) do
    case Joken.peek_header(token) do
      {:ok, header} when is_map(header) -> {:ok, header}
      _error -> {:error, :expected_header_map}
    end
  end

  defp generate_signer(%{"typ" => "JWT", "alg" => alg}, secret) when alg in @algorithms do
    {:ok, Joken.Signer.create(alg, secret)}
  end

  defp generate_signer(_header, _secret), do: {:error, :error_generating_signer}
end
