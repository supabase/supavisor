defmodule Supavisor.PromEx.Plugins.JWTAuth do
  @moduledoc """
  PromEx plugin counting successful and rejected JWT authorizations by
  verification method (`:hmac`, `:jwks`, or `:unknown` for rejections whose
  token has no parsable `alg`) and pipeline (`:api`, `:metrics`).

  This is the adoption signal for deciding when it's safe to stop accepting
  the shared HMAC secret on a pipeline that had AWS-identity JWKS auth
  enabled. `Supavisor.JWT.authorize/2` emits the underlying
  `[:supavisor, :jwt_auth, :ok | :rejected]` telemetry events.
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
      )
    ]
  end
end
