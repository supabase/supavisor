# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :supavisor,
  ecto_repos: [Supavisor.Repo],
  version: Mix.Project.config()[:version],
  env: Mix.env(),
  metrics_disabled: System.get_env("METRICS_DISABLED") == "true",
  switch_active_count: System.get_env("SWITCH_ACTIVE_COUNT", "100") |> String.to_integer(),
  reconnect_retries: System.get_env("RECONNECT_RETRIES", "5") |> String.to_integer(),
  subscribe_retries: System.get_env("SUBSCRIBE_RETRIES", "20") |> String.to_integer()

config :prom_ex, storage_adapter: PromEx.Storage.Peep

# Configures the endpoint
config :supavisor, SupavisorWeb.Endpoint,
  url: [host: "localhost"],
  secret_key_base: "ktyW57usZxrivYdvLo9os7UGcUUZYKchOMHT3tzndmnHuxD09k+fQnPUmxlPMUI3",
  render_errors: [view: SupavisorWeb.ErrorView, accepts: ~w(html json), layout: false],
  pubsub_server: Supavisor.PubSub,
  live_view: [signing_salt: "qf3AEZ7n"]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [
    :request_id,
    :project,
    :user,
    :region,
    :instance_id,
    :mode,
    :type,
    :app_name,
    :peer_ip,
    :local,
    :proxy
  ]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

config :open_api_spex, :cache_adapter, OpenApiSpex.Plug.PersistentTermCache

config :libcluster,
  debug: false,
  topologies: [
    default: [
      # The selected clustering strategy. Required.
      strategy: Cluster.Strategy.Epmd,
      # Configuration for the provided strategy. Optional.
      # config: [hosts: [:"a@127.0.0.1", :"b@127.0.0.1"]],
      # The function to use for connecting nodes. The node
      # name will be appended to the argument list. Optional
      connect: {:net_kernel, :connect_node, []},
      # The function to use for disconnecting nodes. The node
      # name will be appended to the argument list. Optional
      disconnect: {:erlang, :disconnect_node, []},
      # The function to use for listing nodes.
      # This function must return a list of node names. Optional
      list_nodes: {:erlang, :nodes, [:connected]}
    ]
  ]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
