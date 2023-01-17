# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :pg_edge,
  proxy_port: 5555,
  ecto_repos: [PgEdge.Repo]

# Configures the endpoint
config :pg_edge, PgEdgeWeb.Endpoint,
  url: [host: "localhost"],
  render_errors: [view: PgEdgeWeb.ErrorView, accepts: ~w(html json), layout: false],
  pubsub_server: PgEdge.PubSub,
  live_view: [signing_salt: "qf3AEZ7n"]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
