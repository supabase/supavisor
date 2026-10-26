defmodule Supavisor.JWT do
  @moduledoc """
  Authorizes a request's bearer JWT. This is the one entry point for JWT auth:
  it owns everything around verification — header parsing, the token
  blocklist, dispatching to a verifier, telemetry and logging — and leaves the
  cryptography to two verifiers sharing the shape
  `verify(token, config) :: {:ok, claims} | {:error, reason}`:

    * `Supavisor.JWT.SharedSecret` — HMAC (`HS256/384/512`) against a shared secret
    * `Supavisor.JWT.JWKS` — asymmetric tokens (e.g. AWS STS `GetWebIdentityToken`)
      verified against a trusted issuer's JWKS

  ## Choosing the verifier

  The verifier is picked from the token's JWS header `alg`: `HS256/384/512` go to
  `SharedSecret`, anything else goes to `JWKS` if it is configured and is
  rejected otherwise (so where JWKS isn't configured, behaviour is HMAC-only).

  Routing on a header the sender controls is safe because it only selects
  *which* verifier runs, never *how* it verifies. Each verifier pins its own
  algorithm and key (`Joken.Signer.verify/2` allows only the signer's own
  `alg`), so a token that lies about `alg` is rejected rather than verified a
  different way. In particular an `alg: none` token, or an HS256 token forged
  with an issuer's public key as the secret (RFC 8725 §2.1, §3.1), fails
  signature verification. HMAC is the only shared-secret algorithm family
  (RFC 7518 §3.2); the RSA/ECDSA/PSS algorithms need a key pair (§3.3-§3.5),
  and AWS STS only issues `RS256`/`ES384`, so its tokens always take the `JWKS`
  path.

  ## Options

    * `:pipeline` - atom tagging telemetry and logs, e.g. `:api`, `:metrics`
    * `:secret` - `:supavisor` app-env key of the HMAC secret
    * `:blocklist` - `:supavisor` app-env key of the blocked tokens
    * `:jwks` - optional `:supavisor` app-env key of the `Supavisor.JWT.JWKS`
      config (`nil` there disables JWKS)

  ## Telemetry

  `[:supavisor, :jwt_auth, :ok]` (`method`, `pipeline`) and
  `[:supavisor, :jwt_auth, :rejected]` (`method`, `pipeline`, bounded `reason`);
  `method` is `:hmac`, `:jwks` or `:unknown` (no parsable `alg`). See
  `Supavisor.PromEx.Plugins.JWTAuth`.
  """

  require Logger

  alias Supavisor.JWT.JWKS
  alias Supavisor.JWT.SharedSecret

  # JWS `alg`s verified by `SharedSecret`; any other alg goes to `JWKS`.
  @hmac_algorithms SharedSecret.algorithms()

  @type method :: :hmac | :jwks | :unknown
  @type opts :: [
          pipeline: atom(),
          secret: atom(),
          blocklist: atom(),
          jwks: atom()
        ]

  @doc """
  Authorizes the `Authorization: Bearer <token>` header of `conn`.

  Rejections are logged and counted; turning `{:error, reason}` into a response
  is up to the caller.
  """
  @spec authorize(Plug.Conn.t(), opts()) :: {:ok, map()} | {:error, any()}
  def authorize(conn, opts) do
    pipeline = Keyword.fetch!(opts, :pipeline)
    secret = Application.fetch_env!(:supavisor, Keyword.fetch!(opts, :secret))
    blocklist = Application.fetch_env!(:supavisor, Keyword.fetch!(opts, :blocklist))
    jwks_config = opts |> Keyword.get(:jwks) |> jwks_config()

    # Every step fails with `{:error, method, reason}`, `method` being the
    # verifier the token claims (`:unknown` until its `alg` has been read).
    with {:ok, token} <- check_bearer(conn),
         :ok <- check_blocklist(token, blocklist),
         {:ok, method} <- check_header(token),
         :ok <- check_payload(token, method),
         {:ok, claims} <- verify(method, token, secret, jwks_config) do
      :telemetry.execute([:supavisor, :jwt_auth, :ok], %{count: 1}, %{
        method: method,
        pipeline: pipeline
      })

      {:ok, claims}
    else
      {:error, method, reason} -> reject(conn, pipeline, method, reason)
    end
  end

  defp jwks_config(nil), do: nil
  defp jwks_config(key), do: Application.get_env(:supavisor, key)

  # Exactly one `Bearer <token>` header, cleaned once here (the blocklist needs
  # the cleaned form). Anything else — missing, non-Bearer or repeated header —
  # is rejected.
  defp check_bearer(conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, clean_token(token)}
      _ -> {:error, :unknown, :invalid_authorization_header}
    end
  end

  defp clean_token(token), do: Regex.replace(~r/\s|\n/, URI.decode(token), "")

  defp check_blocklist(token, blocklist) do
    if token in blocklist, do: {:error, :unknown, :token_blocklisted}, else: :ok
  end

  defp check_header(token) do
    case Joken.peek_header(token) do
      {:ok, %{"alg" => alg}} when is_binary(alg) ->
        {:ok, if(alg in @hmac_algorithms, do: :hmac, else: :jwks)}

      {:ok, %{} = _header} ->
        {:error, :unknown, :missing_alg}

      _error ->
        {:error, :unknown, :expected_header_map}
    end
  end

  defp check_payload(token, method) do
    case Joken.peek_claims(token) do
      {:ok, claims} when is_map(claims) -> :ok
      _error -> {:error, method, :expected_claims_map}
    end
  end

  defp verify(:hmac, token, secret, _jwks_config),
    do: tag(:hmac, SharedSecret.verify(token, secret))

  defp verify(:jwks, token, _secret, jwks_config) when is_map(jwks_config),
    do: tag(:jwks, JWKS.verify(token, jwks_config))

  defp verify(:jwks, _token, _secret, _jwks_config), do: {:error, :jwks, :jwks_not_configured}

  defp tag(_method, {:ok, claims}), do: {:ok, claims}
  defp tag(method, {:error, reason}), do: {:error, method, reason}

  # Logs *why* a request was rejected (never the token/secret itself) — without
  # this, a failed request is a black box: no way to tell "no auth header" from
  # "blocklisted" from "untrusted issuer" from a JWKS-fetch failure.
  defp reject(conn, pipeline, method, reason) do
    Logger.warning(
      "check_auth: rejected #{pipeline} #{conn.method} #{conn.request_path}: " <>
        inspect(reject_reason_log(reason))
    )

    :telemetry.execute([:supavisor, :jwt_auth, :rejected], %{count: 1}, %{
      method: method,
      pipeline: pipeline,
      reason: reject_reason_metric(reason)
    })

    {:error, reason}
  end

  # Bounded metric tag — never raw error terms or timestamps (label cardinality).
  defp reject_reason_metric(reason) when is_atom(reason), do: reason
  defp reject_reason_metric([{:message, _}, {:claim, "exp"} | _]), do: :token_expired
  defp reject_reason_metric([{:message, _} | _]), do: :invalid_claim
  defp reject_reason_metric(_other), do: :other

  # Log detail: the tag plus the ISO8601 expiry vs now.
  defp reject_reason_log(message: _, claim: "exp", claim_val: exp) when is_integer(exp) do
    {:token_expired,
     exp: exp |> DateTime.from_unix!() |> DateTime.to_iso8601(),
     now: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()}
  end

  defp reject_reason_log(reason), do: reason
end
