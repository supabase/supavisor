defmodule Supavisor.JWT.JWKS.Strategy do
  @moduledoc """
  The `JokenJwks` strategy backing `Supavisor.JWT.JWKS.Token`: fetches
  and caches the JWKS for an issuer configured via `API_JWT_TRUSTED_ISSUER`.

  `Supavisor.Application` starts it only when JWKS auth is configured
  (`API_JWT_TRUSTED_ISSUER` is set).
  """

  use JokenJwks.DefaultStrategyTemplate

  require Logger

  def init_opts(opts) do
    {issuer, opts} = Keyword.pop!(opts, :trusted_issuer)

    Logger.info("Initializing JWKS strategy for issuer: #{issuer}")

    Keyword.merge(opts,
      jwks_url: issuer <> "/.well-known/jwks.json",
      first_fetch_sync: true,
      # AWS's JWKS omits `alg` on RSA keys — see JWKS.AlgFixupMiddleware's moduledoc.
      http_middlewares: [Supavisor.JWT.JWKS.AlgFixupMiddleware]
    )
  end
end
