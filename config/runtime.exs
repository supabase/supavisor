import Config

require Logger

parse_integer_list = fn numbers when is_binary(numbers) ->
  numbers
  |> String.split(",", trim: true)
  |> Enum.map(&String.to_integer/1)
end

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

    region =
      Enum.find_value(~W[CLUSTER_ID LOCATION_ID REGION], &System.get_env/1)
      |> String.replace("-", "_")

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
    |> Helpers.cert_to_bin()
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

db_socket_options =
  if System.get_env("SUPAVISOR_DB_IP_VERSION") == "ipv6",
    do: [:inet6],
    else: [:inet]

reconnect_retries =
  System.get_env("RECONNECT_RETRIES", "5")
  |> String.to_integer()
  |> case do
    -1 -> :infinity
    n -> n
  end

if config_env() != :test do
  config :supavisor,
    session_proxy_ports:
      System.get_env("SESSION_PROXY_PORTS", "12100,12101,12102,12103")
      |> parse_integer_list.(),
    transaction_proxy_ports:
      System.get_env("TRANSACTION_PROXY_PORTS", "12104,12105,12106,12107")
      |> parse_integer_list.(),
    availability_zone: System.get_env("AVAILABILITY_ZONE"),
    region: System.get_env("REGION") || System.get_env("FLY_REGION"),
    fly_alloc_id: System.get_env("FLY_ALLOC_ID"),
    jwt_claim_validators: System.get_env("JWT_CLAIM_VALIDATORS", "{}") |> JSON.decode!(),
    api_jwt_secret: System.get_env("API_JWT_SECRET"),
    metrics_jwt_secret: System.get_env("METRICS_JWT_SECRET"),
    proxy_port_transaction:
      System.get_env("PROXY_PORT_TRANSACTION", "6543") |> String.to_integer(),
    proxy_port_session: System.get_env("PROXY_PORT_SESSION", "5432") |> String.to_integer(),
    proxy_port: System.get_env("PROXY_PORT", "5412") |> String.to_integer(),
    prom_poll_rate: System.get_env("PROM_POLL_RATE", "15000") |> String.to_integer(),
    global_upstream_ca: upstream_ca,
    global_downstream_cert: downstream_cert,
    global_downstream_key: downstream_key,
    reconnect_on_db_close: System.get_env("RECONNECT_ON_DB_CLOSE") == "true",
    reconnect_retries: reconnect_retries,
    api_blocklist: System.get_env("API_TOKEN_BLOCKLIST", "") |> String.split(","),
    metrics_blocklist: System.get_env("METRICS_TOKEN_BLOCKLIST", "") |> String.split(","),
    node_host: System.get_env("NODE_IP", "127.0.0.1")

  config :supavisor, Supavisor.Repo,
    url: System.get_env("DATABASE_URL", "ecto://postgres:postgres@localhost:6432/postgres"),
    pool_size: System.get_env("DB_POOL_SIZE", "25") |> String.to_integer(),
    ssl_opts: [
      verify: :verify_none
    ],
    parameters: [
      application_name: "supavisor_meta"
    ],
    socket_options: db_socket_options

  config :supavisor, Supavisor.Vault,
    ciphers: [
      default: {
        Cloak.Ciphers.AES.GCM,
        tag: "AES.GCM.V1", key: System.get_env("VAULT_ENC_KEY")
      }
    ]
end

if path = System.get_env("SUPAVISOR_LOG_FILE_PATH") do
  config :logger, :default_handler,
    config: [
      file: to_charlist(path),
      file_check: 1000,
      max_no_files: 5,
      # 8 MiB as a max file size
      max_no_bytes: 8 * 1024 * 1024
    ]
end

if System.get_env("SUPAVISOR_LOG_FORMAT") == "json" do
  config :logger, :default_handler,
    formatter:
      {Supavisor.Logger.LogflareFormatter,
       %{
         # metadata: metadata,
         top_level: [:project],
         context: []
       }}
end

if path = System.get_env("SUPAVISOR_ACCESS_LOG_FILE_PATH") do
  config :supavisor, :logger, [
    {:handler, :access_log, :logger_std_h,
     %{
       level: :error,
       formatter:
         Logger.Formatter.new(
           format: "$dateT$timeZ $metadata[$level] $message\n",
           color: false,
           metadata: [:peer_ip],
           utc_log: true
         ),
       filter_default: :stop,
       filters: [
         exchange: {&Supavisor.Logger.Filters.filter_client_handler/2, :exchange}
       ],
       config: %{
         file: to_charlist(path),
         # Keep the file clean on each startup
         modes: [:write]
       }
     }}
  ]
end

config :logger,
  backends: [:console]

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
