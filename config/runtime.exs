import Config

if config_env() == :prod do
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  app_name =
    System.get_env("FLY_APP_NAME") ||
      raise "APP_NAME not available"

  config :supavisor, SupavisorWeb.Endpoint,
    server: true,
    url: [host: "#{app_name}.fly.dev", port: 80],
    http: [
      port: String.to_integer(System.get_env("PORT") || "4000"),
      transport_options: [
        max_connections: String.to_integer(System.get_env("MAX_CONNECTIONS") || "16384"),
        num_acceptors: String.to_integer(System.get_env("NUM_ACCEPTORS") || "100"),
        # IMPORTANT: support IPv6 addresses
        socket_opts: [:inet6]
      ]
    ],
    secret_key_base: secret_key_base
end

if config_env() != :test do
  config :supavisor,
    fly_region: System.get_env("FLY_REGION"),
    fly_alloc_id: System.get_env("FLY_ALLOC_ID"),
    jwt_claim_validators: System.get_env("JWT_CLAIM_VALIDATORS", "{}") |> Jason.decode!(),
    api_jwt_secret: System.get_env("API_JWT_SECRET"),
    metrics_jwt_secret: System.get_env("METRICS_JWT_SECRET"),
    proxy_port: System.get_env("PROXY_PORT", "7654") |> String.to_integer(),
    prom_poll_rate: System.get_env("PROM_POLL_RATE", "15000") |> String.to_integer()

  config :supavisor, Supavisor.Repo,
    hostname: System.get_env("DB_HOST", "localhost"),
    username: System.get_env("DB_USER", "postgres"),
    password: System.get_env("DB_PASSWORD", "postgres"),
    database: System.get_env("DB_NAME", "postgres"),
    port: System.get_env("DB_PORT", "6432"),
    pool_size: System.get_env("DB_POOL_SIZE", "5") |> String.to_integer(),
    parameters: [
      application_name: "supavisor_meta"
    ]

  config :supavisor, Supavisor.Vault,
    ciphers: [
      default: {
        Cloak.Ciphers.AES.GCM,
        tag: "AES.GCM.V1", key: System.get_env("VAULT_ENC_KEY")
      }
    ]
end
