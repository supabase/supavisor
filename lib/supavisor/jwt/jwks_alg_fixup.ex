defmodule Supavisor.Jwt.JwksAlgFixup do
  @moduledoc """
  AWS's outbound-identity-federation JWKS omits `"alg"` on RSA keys (a valid,
  RFC 7517-*optional* field — AWS's own docs show an example JWKS response
  with an RSA key entry that has no `"alg"`, alongside an EC key that does).

  `joken_jwks` requires `"alg"` on every key, or a single `explicit_alg`
  option applied to *all* keys — which doesn't work here, since AWS's
  `GetWebIdentityToken` supports both RS256 and ES384, and a single account's
  JWKS can (and does) mix both key types in one response. Without this fixup,
  `JokenJwks.DefaultStrategyTemplate.fetch_signers/3` fails the *entire*
  fetch with `{:error, :no_algorithm_supplied}` the moment it hits the first
  alg-less key — logged as "Failed to fetch signers".

  Wired in via `init_opts/1`'s `http_middlewares`. `JokenJwks.HttpFetcher`
  builds its Tesla client as `[JSON, Retry] ++ http_middlewares` — meaning
  anything passed via `http_middlewares` runs *inside* (closer to the
  adapter than) the JSON-decoding middleware, since Tesla unwinds responses
  in reverse of the request order. So at the point this middleware runs,
  `env.body` is still the raw, not-yet-decoded JSON string.

  This decodes it once, fixes up the keys, and leaves `env.body` as the
  resulting *map* rather than re-encoding back to a string. The outer JSON
  middleware's own `decodable?/2` check only decodes binary/list/stream
  bodies — a map fails all of those, so its decode step becomes a no-op and
  passes our already-fixed map straight through. One decode, zero encodes.

  Example response from the:
  iex> JokenJwks.HttpFetcher.fetch_signers("https://a1e49c3a-19a8-4e0b-a11a-80d7e2c30bff.tokens.sts.global.api.aws/.well-known/jwks.json", [])
  {:ok,
   [
     %{
       "e" => "AQAB",
       "kid" => "RSA_1",
       "kty" => "RSA",
       "n" => "2WyS92F63WUyrJYZyG9Id2znCUflvioFDoy0kEmuNTC9Y-3QQl7Zy4ip8dZSi8iuI6Z2Ie6yXULOjBog-gpXicTG7iSupQNLml9j4IeMvVFR2ImJjoKP1OPuWcTMuGnb6Fwz7rocDtV0wNNVRw42pXJ9ifc5cFYW6pE7wTmUNSODsn2WfTjM-NVdahuPz_wwRvXkpAx3Hoi3kExExC8Agd1uBq-R1lBlCF-XT74-1i_cFg2pLPQMFz1jfoSwmNI1IQnyKMjVp3rrq68qg8Xu0Krm5EtD80yLRpn28XofzbV6PcsCIDutgWi1kZB3R9KqTTjC5O7psHKImyIrm7ZwBw",
       "use" => "sig"
     },
     %{
       "alg" => "ES384",
       "crv" => "P-384",
       "kid" => "EC384_1",
       "kty" => "EC",
       "use" => "sig",
       "x" => "ggXqRyj9O2bzgEgUxBoVlH9pr92JIouCRN45_cTDjfpFUA6AbNOWeNmyKPjR_puK",
       "y" => "0rLAuiGUmzwM3NnMHlGkd7oimOMDpuq33fwwSsNTct-7ljUzz3iaFnzGL4ypqgTS"
     }
   ]}
  """

  @behaviour Tesla.Middleware

  @impl true
  def call(env, next, _opts) do
    with {:ok, env} <- Tesla.run(env, next) do
      {:ok, update_in(env.body, &fixup_body/1)}
    end
  end

  defp fixup_body(body) when is_binary(body) do
    case JSON.decode(body) do
      {:ok, %{"keys" => keys} = decoded} when is_list(keys) ->
        %{decoded | "keys" => Enum.map(keys, &infer_alg/1)}

      _ ->
        body
    end
  end

  defp fixup_body(%{"keys" => keys} = body) when is_list(keys) do
    %{body | "keys" => Enum.map(keys, &infer_alg/1)}
  end

  defp fixup_body(body), do: body

  defp infer_alg(%{"alg" => alg} = key) when is_binary(alg), do: key
  defp infer_alg(%{"kty" => "RSA"} = key), do: Map.put(key, "alg", "RS256")
  defp infer_alg(%{"kty" => "EC", "crv" => "P-384"} = key), do: Map.put(key, "alg", "ES384")
  defp infer_alg(key), do: key
end
