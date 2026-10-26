defmodule Supavisor.JWT.JWKS.Strategy do
  @moduledoc """
  The `JokenJwks` strategy backing `Supavisor.JWT.JWKS.Token`: fetches
  and caches the JWKS for the single trusted AWS STS issuer configured via
  `API_JWT_TRUSTED_ISSUER`.


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
          # AWS's JWKS omits `alg` on RSA keys — see JWKS.AlgFixup's moduledoc.
          http_middlewares: [Supavisor.JWT.JWKS.AlgFixup]
        )

      _ ->
        # `DefaultStrategyTemplate.start_link/2` requires a truthy `jwks_url`
        # even though `should_start: false` means it's never started.
        Keyword.merge(opts, jwks_url: :undefined, should_start: false)
    end
  end
end
