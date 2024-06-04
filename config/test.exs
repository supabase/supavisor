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
  prom_poll_rate: 500,
  api_blocklist: [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJibG9ja2VkIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.y-V3D1N2e8UTXc5PJzmV9cqMteq0ph2wl0yt42akQgA"
  ],
  metrics_blocklist: []

config :supavisor, Supavisor.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "supavisor_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10,
  port: 6432

config :partisan,
  # Which overlay to use
  peer_service_manager: :partisan_pluggable_peer_service_manager,
  # The listening port for Partisan TCP/IP connections
  peer_port: 10200,
  channels: [data: %{parallelism: 1}],
  # Encoding for pid(), reference() and names
  pid_encoding: false,
  ref_encoding: false,
  remote_ref_format: :improper_list

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

config :partisan,
  peer_service_manager: :partisan_pluggable_peer_service_manager,
  listen_addrs: [
    {
      System.get_env("PARTISAN_PEER_IP", "127.0.0.1"),
      String.to_integer(System.get_env("PARTISAN_PEER_PORT", "10200"))
    }
  ],
  channels: [
    data: %{parallelism: System.get_env("PARTISAN_PARALLELISM", "5") |> String.to_integer()}
  ],
  pid_encoding: false,
  ref_encoding: false,
  remote_ref_format: :improper_list
