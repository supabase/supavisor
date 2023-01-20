import Config

if config_env() == :prod do
  # database_url =
  #   System.get_env("DATABASE_URL") ||
  #     raise """
  #     environment variable DATABASE_URL is missing.
  #     For example: ecto://USER:PASS@HOST/DATABASE
  #     """

  maybe_ipv6 = if System.get_env("ECTO_IPV6"), do: [:inet6], else: []

  # config :pg_edge, PgEdge.Repo,
  #   # ssl: true,
  #   url: database_url,
  #   pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
  #   socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
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
  config :pg_edge, PgEdge.DevTenant,
    db_host: System.get_env("TENANT_DB_HOST", "127.0.0.1"),
    db_port: System.get_env("TENANT_DB_PORT", "6432") |> String.to_integer(),
    db_name: System.get_env("TENANT_DB_NAME", "postgres"),
    db_user:  System.get_env("TENANT_DB_USER", "postgres"),
    db_password: System.get_env("TENANT_DB_PASSWORD", "postgres"),
    connect_timeout: 5000,
    application_name: "pg_edge",
    pool_size: System.get_env("DB_POOL_SIZE", "50") |> String.to_integer()
end
