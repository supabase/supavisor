defmodule Supavisor.Jwt.JwksStrategy do
  @moduledoc """
  The `JokenJwks` strategy backing `Supavisor.Jwt.AwsIdentity.Token`: fetches
  and caches the JWKS for the single trusted AWS STS issuer configured via
  `API_JWT_TRUSTED_ISSUER`.

  Supavisor only ever needs to trust one issuer at a time: consumers are
  expected to `sts:AssumeRole` into the `supavisor-api` IAM role (see
  `pulumi/supavisor-iam`) before calling `GetWebIdentityToken`, so every
  resulting token's issuer is this pooler cluster's own AWS account —
  regardless of which account the calling service actually runs in. AWS
  accounts are 1:1 with STS issuers, so that's a single, fixed JWKS source.
  If that assumption ever stops holding (e.g. a consumer needs to present a
  token from its own account directly), revisit.

  Always present in `Supavisor.Application`'s supervision tree. When
  `API_JWT_TRUSTED_ISSUER` isn't set, `init_opts/1`
  returns `should_start: false`, which `JokenJwks.DefaultStrategyTemplate`
  treats as `:ignore` — no process ends up in the supervision tree, no
  scheduled fetch, no outbound HTTP.
  """

  use JokenJwks.DefaultStrategyTemplate

  def init_opts(opts) do
    case Application.get_env(:supavisor, :api_jwks_config) do
      %{trusted_issuer: issuer} when is_binary(issuer) and issuer != "" ->
        jwks_url = String.trim_trailing(issuer, "/") <> "/.well-known/jwks.json"

        Keyword.merge(opts,
          jwks_url: jwks_url,
          first_fetch_sync: true,
          # AWS's JWKS omits `alg` on RSA keys — see JwksAlgFixup's moduledoc.
          http_middlewares: [Supavisor.Jwt.JwksAlgFixup]
        )

      _ ->
        # `DefaultStrategyTemplate.start_link/2` requires a truthy `jwks_url`
        # even though `should_start: false` means it's never started.
        Keyword.merge(opts, jwks_url: "unused", should_start: false)
    end
  end
end
