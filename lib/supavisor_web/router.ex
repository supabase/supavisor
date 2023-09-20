defmodule SupavisorWeb.Router do
  use SupavisorWeb, :router

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
    plug(:check_auth, :api_jwt_secret)
  end

  pipeline :metrics do
    plug(:check_auth, :metrics_jwt_secret)
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
    delete("/tenants/:external_id", TenantController, :delete)
    get("/tenants/:external_id/terminate", TenantController, :terminate)
    get("/health", TenantController, :health)

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

  defp check_auth(conn, secret_key) do
    secret = Application.fetch_env!(:supavisor, secret_key)

    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, _claims} <- Supavisor.Jwt.authorize(token, secret) do
      conn
    else
      _ ->
        conn
        |> send_resp(403, "")
        |> halt()
    end
  end
end
