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

  config :pg_edge, PgEdgeWeb.Endpoint,
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
  config :pg_edge,
    jwt_claim_validators: System.get_env("JWT_CLAIM_VALIDATORS", "{}") |> Jason.decode!(),
    api_jwt_secret: System.get_env("API_JWT_SECRET"),
    db_enc_key: System.get_env("DB_ENC_KEY")

  config :pg_edge, PgEdge.Repo,
    # priv: "priv/repo/pgedge",
    # migration_default_prefix: "pgedge",
    hostname: System.get_env("DB_HOST", "localhost"),
    username: System.get_env("DB_USER", "postgres"),
    password: System.get_env("DB_PASSWORD", "postgres"),
    database: System.get_env("DB_NAME", "postgres"),
    port: System.get_env("DB_PORT", "6432"),
    pool_size: System.get_env("DB_POOL_SIZE", "5") |> String.to_integer(),
    parameters: [
      application_name: "pg_edge_meta"
    ]

  config :pg_edge, PgEdge.DevTenant,
    db_host: System.get_env("TENANT_DB_HOST", "127.0.0.1"),
    db_port: System.get_env("TENANT_DB_PORT", "6432") |> String.to_integer(),
    db_name: System.get_env("TENANT_DB_NAME", "postgres"),
    db_user: System.get_env("TENANT_DB_USER", "postgres"),
    db_password: System.get_env("TENANT_DB_PASSWORD", "postgres"),
    connect_timeout: 5000,
    application_name: "pg_edge",
    pool_size: System.get_env("DB_POOL_SIZE", "50") |> String.to_integer()
end
