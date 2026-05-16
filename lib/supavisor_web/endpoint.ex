defmodule SupavisorWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :supavisor

  # The session will be stored in the cookie and signed,
  # this means its contents can be read but not tampered with.
  # Set :encryption_salt if you would also like to encrypt it.
  @session_options [
    store: :cookie,
    key: "_supavisor_key",
    signing_salt: "zJOrGxcM"
  ]

  socket "/live", Phoenix.LiveView.Socket, websocket: [connect_info: [session: @session_options]]

  plug Phoenix.LiveDashboard.RequestLogger,
    param_key: "request_logger",
    cookie_key: "request_logger"

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  # Reads + JSON-decodes the body for POST /sql requests carrying the
  # Neon-Connection-String header, regardless of Content-Type — required
  # because the @neondatabase/serverless driver omits it. Runs before
  # Plug.Parsers so that body_params is already populated by the time
  # Plug.Parsers gets the conn (Plug.Parsers short-circuits when it
  # sees a non-Unfetched body_params).
  plug Supavisor.HttpSql.NeonBodyParser, json_decoder: Phoenix.json_library()

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.MethodOverride
  plug Plug.Head
  plug Plug.Session, @session_options
  plug SupavisorWeb.Router
end
