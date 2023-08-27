import Config

config :supavisor,
  region: "eu",
  fly_alloc_id: "123e4567-e89b-12d3-a456-426614174000",
  api_jwt_secret: "dev",
  metrics_jwt_secret: "dev",
  jwt_claim_validators: %{},
  proxy_port_session: System.get_env("PROXY_PORT_SESSION", "7653") |> String.to_integer(),
  proxy_port_transaction: System.get_env("PROXY_PORT_TRANSACTION", "7654") |> String.to_integer(),
  secondary_proxy_port: 7655,
  secondary_http: 4003,
  prom_poll_rate: 500

config :supavisor, Supavisor.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "supavisor_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10,
  port: 6432

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :supavisor, SupavisorWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  server: false

config :supavisor, Supavisor.Vault,
  ciphers: [
    default: {
      Cloak.Ciphers.AES.GCM,
      tag: "AES.GCM.V1", key: "aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7"
    }
  ]

# Print only warnings and errors during test
config :logger, :console,
  level: :info,
  format: "$time [$level] $message $metadata\n",
  metadata: [:error_code, :file, :line, :pid, :project, :user, :mode]

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime
