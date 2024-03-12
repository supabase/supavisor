import Config

require Logger
alias Supavisor.Helpers, as: H

secret_key_base =
  if config_env() in [:dev, :test] do
    "3S1V5RyqQcuPrMVuR4BjH9XBayridj56JA0EE6wYidTEc6H84KSFY6urVX7GfOhK"
  else
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """
  end

config :supavisor, SupavisorWeb.Endpoint,
  server: true,
  http: [
    port: String.to_integer(System.get_env("PORT") || "4000"),
    transport_options: [
      max_connections: String.to_integer(System.get_env("MAX_CONNECTIONS") || "1000"),
      num_acceptors: String.to_integer(System.get_env("NUM_ACCEPTORS") || "100"),
      socket_opts: [
        System.get_env("ADDR_TYPE", "inet")
        |> tap(fn addr_type ->
          if addr_type not in ["inet", "inet6"] do
            raise "ADDR_TYPE env var is invalid: #{inspect(addr_type)}"
          end
        end)
        |> String.to_atom()
      ]
    ]
  ],
  secret_key_base: secret_key_base

topologies = []

topologies =
  if System.get_env("DNS_POLL") do
    dns_poll = [
      strategy: Cluster.Strategy.DNSPoll,
      config: [
        polling_interval: 5_000,
        query: System.get_env("DNS_POLL"),
        node_basename:
          System.get_env("NODE_NAME") || System.get_env("FLY_APP_NAME") || "supavisor"
      ]
    ]

    Keyword.put(topologies, :dns_poll, dns_poll)
  else
    topologies
  end

topologies =
  if System.get_env("CLUSTER_NODES") do
    epmd = [
      strategy: Cluster.Strategy.Epmd,
      config: [
        hosts:
          System.get_env("CLUSTER_NODES", "")
          |> String.split(",")
          |> Enum.map(&String.to_atom/1)
      ],
      connect: {:net_kernel, :connect_node, []},
      disconnect: {:erlang, :disconnect_node, []},
      list_nodes: {:erlang, :nodes, [:connected]}
    ]

    Keyword.put(topologies, :epmd, epmd)
  else
    topologies
  end

topologies =
  if System.get_env("CLUSTER_POSTGRES") && Application.spec(:supavisor, :vsn) do
    %Version{major: maj, minor: min} =
      Application.spec(:supavisor, :vsn) |> List.to_string() |> Version.parse!()

    region = System.get_env("REGION") |> String.replace("-", "_")

    postgres = [
      strategy: Cluster.Strategy.Postgres,
      config: [
        url: System.get_env("DATABASE_URL", "ecto://postgres:postgres@localhost:6432/postgres"),
        heartbeat_interval: 5_000,
        channel_name: "supavisor_#{region}_#{maj}_#{min}"
      ]
    ]

    Keyword.put(topologies, :postgres, postgres)
  else
    topologies
  end

config :libcluster,
  debug: false,
  topologies: topologies

upstream_ca =
  if path = System.get_env("GLOBAL_UPSTREAM_CA_PATH") do
    File.read!(path)
    |> H.cert_to_bin()
    |> case do
      {:ok, bin} ->
        Logger.info("Loaded upstream CA from $GLOBAL_UPSTREAM_CA_PATH",
          ansi_color: :green
        )

        bin

      {:error, _} ->
        raise "There is no valid certificate in $GLOBAL_UPSTREAM_CA_PATH"
    end
  end

downstream_cert =
  if path = System.get_env("GLOBAL_DOWNSTREAM_CERT_PATH") do
    if File.exists?(path) do
      Logger.info("Loaded downstream cert from $GLOBAL_DOWNSTREAM_CERT_PATH, path: #{path}",
        ansi_color: :green
      )

      path
    else
      raise "There is no such file in $GLOBAL_DOWNSTREAM_CERT_PATH"
    end
  end

downstream_key =
  if path = System.get_env("GLOBAL_DOWNSTREAM_KEY_PATH") do
    if File.exists?(path) do
      Logger.info("Loaded downstream key from $GLOBAL_DOWNSTREAM_KEY_PATH, path: #{path}",
        ansi_color: :green
      )

      path
    else
      raise "There is no such file in $GLOBAL_DOWNSTREAM_KEY_PATH"
    end
  end

if config_env() != :test do
  config :supavisor,
    region: System.get_env("REGION") || System.get_env("FLY_REGION"),
    fly_alloc_id: System.get_env("FLY_ALLOC_ID"),
    jwt_claim_validators: System.get_env("JWT_CLAIM_VALIDATORS", "{}") |> Jason.decode!(),
    api_jwt_secret: System.get_env("API_JWT_SECRET"),
    metrics_jwt_secret: System.get_env("METRICS_JWT_SECRET"),
    proxy_port_transaction:
      System.get_env("PROXY_PORT_TRANSACTION", "6543") |> String.to_integer(),
    proxy_port_session: System.get_env("PROXY_PORT_SESSION", "5432") |> String.to_integer(),
    prom_poll_rate: System.get_env("PROM_POLL_RATE", "15000") |> String.to_integer(),
    global_upstream_ca: upstream_ca,
    global_downstream_cert: downstream_cert,
    global_downstream_key: downstream_key,
    reconnect_on_db_close: System.get_env("RECONNECT_ON_DB_CLOSE") == "true"

  config :supavisor, Supavisor.Repo,
    url: System.get_env("DATABASE_URL", "ecto://postgres:postgres@localhost:6432/postgres"),
    pool_size: System.get_env("DB_POOL_SIZE", "25") |> String.to_integer(),
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

if System.get_env("LOGS_ENGINE") == "logflare" do
  if !System.get_env("LOGFLARE_API_KEY") or !System.get_env("LOGFLARE_SOURCE_ID") do
    raise """
    Environment variable LOGFLARE_API_KEY or LOGFLARE_SOURCE_ID is missing.
    Check those variables or choose another LOGS_ENGINE.
    """
  end

  config :logger,
    backends: [LogflareLogger.HttpBackend]
end
