import Config

config :pg_edge,
  api_jwt_secret: "dev",
  jwt_claim_validators: %{},
  proxy_port: System.get_env("PROXY_PORT", "7654") |> String.to_integer()

config :pg_edge, PgEdge.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "pg_edge_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10,
  port: 6432

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :pg_edge, PgEdgeWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "/r65VZub52YDf/CjNMeYmkJ8AitZZPIMRnC64f7P+LTOo87+/rqjydvAE65OK0/1",
  server: false

config :pg_edge, PgEdge.Vault,
  ciphers: [
    default: {
      Cloak.Ciphers.AES.GCM,
      tag: "AES.GCM.V1", key: "aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7"
    }
  ]

# Print only warnings and errors during test
config :logger, level: :warn

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime
