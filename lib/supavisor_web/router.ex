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

  scope "/", SupavisorWeb do
    pipe_through(:browser)

    get("/", PageController, :index)
  end

  scope "/api", SupavisorWeb do
    pipe_through(:api)

    resources("/tenants", TenantController)
  end

  scope "/metrics", SupavisorWeb do
    pipe_through(:metrics)

    get("/", MetricsController, :index)
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
