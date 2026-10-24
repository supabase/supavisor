defmodule SupavisorWeb.Router do
  use SupavisorWeb, :router

  require Logger

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_live_flash)
    plug(:put_root_layout, {SupavisorWeb.LayoutView, :root})
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
  end

  pipeline :api do
    plug(:accepts, ["json"])

    plug(:check_auth,
      pipeline: :api,
      secret: :api_jwt_secret,
      blocklist: :api_blocklist,
      jwks: :api_jwks_config
    )

    plug(OpenApiSpex.Plug.PutApiSpec, module: SupavisorWeb.ApiSpec)
  end

  pipeline :metrics do
    plug(:check_auth,
      pipeline: :metrics,
      secret: :metrics_jwt_secret,
      blocklist: :metrics_blocklist
    )
  end

  pipeline :openapi do
    plug(OpenApiSpex.Plug.PutApiSpec, module: SupavisorWeb.ApiSpec)
  end

  scope "/swaggerui" do
    pipe_through(:browser)
    get("/", OpenApiSpex.Plug.SwaggerUI, path: "/api/openapi")
  end

  scope "/api" do
    pipe_through(:openapi)
    get("/openapi", OpenApiSpex.Plug.RenderSpec, [])
  end

  # websocket pg proxy
  scope "/v2" do
    get("/", SupavisorWeb.WsProxy, [])
  end

  scope "/api", SupavisorWeb do
    pipe_through(:api)

    get("/tenants/:external_id", TenantController, :show)
    put("/tenants/:external_id", TenantController, :update)
    patch("/tenants/:external_id", TenantController, :patch)
    delete("/tenants/:external_id", TenantController, :delete)
    get("/tenants/:external_id/terminate", TenantController, :terminate)

    post(
      "/tenants/:external_id/update_auth_credentials",
      TenantController,
      :update_auth_credentials
    )

    get("/tenants/:external_id/network_bans", TenantController, :list_network_bans)
    delete("/tenants/:external_id/network_bans", TenantController, :clear_network_bans)

    get("/tenants/:external_id/pools", PoolController, :index)

    get("/health", TenantController, :health)
    post("/rebalance", PoolController, :rebalance)

    get("/clusters/:alias", ClusterController, :show)
    put("/clusters/:alias", ClusterController, :update)
    delete("/clusters/:alias", ClusterController, :delete)
    # get("/clusters/:alias/terminate", ClusterController, :terminate)
  end

  scope "/metrics", SupavisorWeb do
    pipe_through(:metrics)

    get("/", MetricsController, :index)
    get("/:external_id", MetricsController, :tenant)
  end

  # Other scopes may use custom stacks.
  # scope "/api", SupavisorWeb do
  #   pipe_through :api
  # end

  # Enables LiveDashboard only for development
  #
  # If you want to use the LiveDashboard in production, you should put
  # it behind authentication and allow only admins to access it.
  # If your application does not have an admins-only section yet,
  # you can use Plug.BasicAuth to set up some basic authentication
  # as long as you are also using SSL (which you should anyway).
  if Mix.env() in [:dev, :test] do
    import Phoenix.LiveDashboard.Router

    scope "/" do
      pipe_through(:browser)

      live_dashboard("/dashboard", metrics: SupavisorWeb.Telemetry)
    end
  end

  defp check_auth(%{request_path: "/api/health"} = conn, _), do: conn

  # With `jwks:` (`:api`): the shared HMAC secret or, if that config is set, an
  # AWS-identity JWT verified via JWKS (`Supavisor.Jwt.AwsIdentity`). See
  # `Supavisor.Jwt.authorize_dual/3`.
  #
  # Without it (`:metrics`): HMAC only.
  defp check_auth(conn, opts) do
    pipeline = Keyword.fetch!(opts, :pipeline)
    secret = Application.fetch_env!(:supavisor, Keyword.fetch!(opts, :secret))
    blocklist = Application.fetch_env!(:supavisor, Keyword.fetch!(opts, :blocklist))

    authorize =
      case Keyword.fetch(opts, :jwks) do
        {:ok, jwks_key} ->
          jwks_config = Application.get_env(:supavisor, jwks_key)
          &Supavisor.Jwt.authorize_dual(&1, secret, jwks_config)

        :error ->
          &hmac_authorize(&1, secret)
      end

    with {:ok, token} <- bearer_token(conn),
         :ok <- check_blocklist(token, blocklist),
         {:ok, method, _claims} <- authorize.(token) do
      :telemetry.execute([:supavisor, :jwt_auth, :ok], %{count: 1}, %{
        method: method,
        pipeline: pipeline
      })

      conn
    else
      :invalid_authorization_header ->
        reject(conn, pipeline, :unknown, :invalid_authorization_header)

      :blocklisted ->
        reject(conn, pipeline, :unknown, :token_blocklisted)

      {:error, method, reason} ->
        reject(conn, pipeline, method, reason)
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, Supavisor.Jwt.clean_token(token)}
      _ -> :invalid_authorization_header
    end
  end

  defp check_blocklist(token, blocklist), do: if(token in blocklist, do: :blocklisted, else: :ok)

  defp hmac_authorize(token, secret) do
    case Supavisor.Jwt.verify(token, secret) do
      {:ok, claims} -> {:ok, :hmac, claims}
      {:error, reason} -> {:error, :hmac, reason}
    end
  end

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

    conn
    |> send_resp(403, "")
    |> halt()
  end

  defp reject_reason_metric(reason) when is_atom(reason), do: reason
  defp reject_reason_metric([{:message, _}, {:claim, "exp"} | _]), do: :token_expired
  defp reject_reason_metric([{:message, _} | _]), do: :invalid_claim
  defp reject_reason_metric(_other), do: :other

  defp reject_reason_log(message: _, claim: "exp", claim_val: exp) when is_integer(exp) do
    {:token_expired,
     exp: exp |> DateTime.from_unix!() |> DateTime.to_iso8601(),
     now: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()}
  end

  defp reject_reason_log(reason), do: reason
end
