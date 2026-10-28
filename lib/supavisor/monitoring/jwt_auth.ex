defmodule Supavisor.PromEx.Plugins.JWTAuth do
  @moduledoc """
  PromEx plugin counting successful and rejected JWT authorizations by
  verification method (`:hmac`, `:jwks`, or `:unknown` for rejections whose
  token has no parsable `alg`) and pipeline (`:api`, `:metrics`).

  This is the adoption signal for deciding when it's safe to stop accepting
  the shared HMAC secret on a pipeline that had AWS-identity JWKS auth
  enabled. `Supavisor.JWT.authorize/2` emits the underlying
  `[:supavisor, :jwt_auth, :ok | :rejected]` telemetry events.

  It also counts what `JokenJwks` reports about the issuer's JWKS: key fetches,
  refetches after an unknown `kid`, and HTTP fetch exceptions. A non-200
  response or an unusable body is logged by `JokenJwks` but emits no event.
  """

  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    [
      Event.build(
        :supavisor_jwt_auth_event_metrics,
        [
          counter(
            [:supavisor, :jwt_auth, :ok],
            event_name: [:supavisor, :jwt_auth, :ok],
            description: "Count of successful JWT authorizations, tagged by verification method.",
            tags: [:method, :pipeline]
          ),
          counter(
            [:supavisor, :jwt_auth, :rejected],
            event_name: [:supavisor, :jwt_auth, :rejected],
            description:
              "Count of rejected JWT authorizations, tagged by the (unverified) method the " <>
                "token claimed, the pipeline and a bounded rejection reason.",
            tags: [:method, :pipeline, :reason]
          )
        ]
      ),
      Event.build(
        :supavisor_jwks_event_metrics,
        [
          counter(
            [:supavisor, :jwks, :fetch, :ok],
            event_name: [:joken_jwks, :default_strategy, :signers],
            description: "Count of successful fetches of the trusted issuer's JWKS."
          ),
          counter(
            [:supavisor, :jwks, :refetch],
            event_name: [:joken_jwks, :default_strategy, :refetch],
            description: "Count of JWKS refetches triggered by a token with an unknown kid."
          ),
          counter(
            [:supavisor, :jwks, :fetch, :exception],
            event_name: [:joken_jwks, :http_fetcher, :exception],
            description: "Count of JWKS HTTP fetches that raised."
          )
        ]
      )
    ]
  end
end
