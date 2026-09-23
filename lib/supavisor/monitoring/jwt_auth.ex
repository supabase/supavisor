defmodule Supavisor.PromEx.Plugins.JwtAuth do
  @moduledoc """
  PromEx plugin counting successful JWT authorizations by verification
  method (`:hmac` vs `:jwks`) and pipeline (`:api`, `:metrics`, ...).

  This is the adoption signal for deciding when it's safe to stop accepting
  the shared HMAC secret on a pipeline that's had AWS-identity JWKS auth
  enabled — see `Supavisor.Jwt.authorize_dual/3` and the `:api` clause of
  `SupavisorWeb.Router.check_auth/2`, which emit the underlying
  `[:supavisor, :jwt_auth]` telemetry event.
  """

  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    [
      Event.build(
        :supavisor_jwt_auth_event_metrics,
        [
          counter(
            [:supavisor, :jwt_auth, :total],
            event_name: [:supavisor, :jwt_auth],
            description: "Count of successful JWT authorizations, tagged by verification method.",
            tags: [:method, :pipeline]
          )
        ]
      )
    ]
  end
end
