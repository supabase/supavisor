import Config

if config_env() == :prod do
  config :supavisor, SupavisorWeb.Endpoint,
    server: true,
    http: [
      port: String.to_integer(System.get_env("PORT") || "4000"),
      transport_options: [
        max_connections: String.to_integer(System.get_env("MAX_CONNECTIONS") || "1000"),
        num_acceptors: String.to_integer(System.get_env("NUM_ACCEPTORS") || "100"),
        # IMPORTANT: support IPv6 addresses
        socket_opts: [:inet6]
      ]
    ]

  config :libcluster,
    debug: false,
    topologies: [
      fly6pn: [
        strategy: Cluster.Strategy.DNSPoll,
        config: [
          polling_interval: 5_000,
          query: System.get_env("DNS_NODES"),
          node_basename: System.get_env("FLY_APP_NAME") || "supavisor"
        ]
      ]
    ]
end

if config_env() != :test do
  config :supavisor,
    region: System.get_env("REGION") || System.get_env("FLY_REGION"),
    fly_alloc_id: System.get_env("FLY_ALLOC_ID"),
    jwt_claim_validators: System.get_env("JWT_CLAIM_VALIDATORS", "{}") |> Jason.decode!(),
    api_jwt_secret: System.get_env("API_JWT_SECRET"),
    metrics_jwt_secret: System.get_env("METRICS_JWT_SECRET"),
    proxy_port: System.get_env("PROXY_PORT", "7654") |> String.to_integer(),
    prom_poll_rate: System.get_env("PROM_POLL_RATE", "15000") |> String.to_integer()

  config :supavisor, Supavisor.Repo,
    url: System.get_env("DATABASE_URL", "ecto://postgres:postgres@localhost:6432/postgres"),
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
