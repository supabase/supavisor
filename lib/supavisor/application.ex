defmodule Supavisor.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  require Logger

  alias Supavisor.Monitoring.PromEx

  @metrics_disabled Application.compile_env(:supavisor, :metrics_disabled, false)

  @impl true
  def start(_type, _args) do
    primary_config = :logger.get_primary_config()

    :ok =
      :logger.set_primary_config(
        :metadata,
        Enum.into(
          [
            region: System.get_env("AVAILABILITY_ZONE") || System.get_env("REGION"),
            instance_id: System.get_env("INSTANCE_ID")
          ],
          primary_config.metadata
        )
      )

    :ok =
      :gen_event.swap_sup_handler(
        :erl_signal_server,
        {:erl_signal_handler, []},
        {Supavisor.SignalHandler, []}
      )

    proxy_ports = [
      {:pg_proxy_transaction, Application.get_env(:supavisor, :proxy_port_transaction),
       :transaction, Supavisor.ClientHandler},
      {:pg_proxy_session, Application.get_env(:supavisor, :proxy_port_session), :session,
       Supavisor.ClientHandler},
      {:pg_proxy, Application.get_env(:supavisor, :proxy_port), :proxy, Supavisor.ClientHandler}
    ]

    for {key, port, mode, handler} <- proxy_ports do
      case :ranch.start_listener(
             key,
             :ranch_tcp,
             %{
               max_connections: String.to_integer(System.get_env("MAX_CONNECTIONS") || "75000"),
               num_acceptors: String.to_integer(System.get_env("NUM_ACCEPTORS") || "100"),
               socket_opts: [port: port, keepalive: true]
             },
             handler,
             %{mode: mode}
           ) do
        {:ok, _pid} ->
          Logger.notice("Proxy started #{mode} on port #{port}")

        error ->
          Logger.error("Proxy on #{port} not started because of #{inspect(error)}")
      end
    end

    :syn.set_event_handler(Supavisor.SynHandler)
    :syn.add_node_to_scopes([:tenants, :availability_zone])

    :syn.join(:availability_zone, Application.get_env(:supavisor, :availability_zone), self(),
      node: node()
    )

    topologies = Application.get_env(:libcluster, :topologies) || []

    children = [
      Supavisor.ErlSysMon,
      {Registry, keys: :unique, name: Supavisor.Registry.Tenants},
      {Registry, keys: :unique, name: Supavisor.Registry.ManagerTables},
      {Registry, keys: :unique, name: Supavisor.Registry.PoolPids},
      {Registry, keys: :duplicate, name: Supavisor.Registry.TenantSups},
      {Registry,
       keys: :duplicate,
       name: Supavisor.Registry.TenantClients,
       partitions: System.schedulers_online()},
      {Registry,
       keys: :duplicate,
       name: Supavisor.Registry.TenantProxyClients,
       partitions: System.schedulers_online()},
      {Cluster.Supervisor, [topologies, [name: Supavisor.ClusterSupervisor]]},
      Supavisor.Repo,
      # Start the Telemetry supervisor
      SupavisorWeb.Telemetry,
      # Start the PubSub system
      {Phoenix.PubSub, name: Supavisor.PubSub},
      {
        PartitionSupervisor,
        child_spec: DynamicSupervisor, strategy: :one_for_one, name: Supavisor.DynamicSupervisor
      },
      Supavisor.Vault,

      # Start the Endpoint (http/https)
      SupavisorWeb.Endpoint
    ]

    Logger.warning("metrics_disabled is #{inspect(@metrics_disabled)}")

    children =
      if @metrics_disabled do
        children
      else
        PromEx.set_metrics_tags()
        children ++ [PromEx, Supavisor.TenantsMetrics, Supavisor.MetricsCleaner]
      end

    # start Cachex only if the node uses names, this is necessary for test setup
    children =
      if node() != :nonode@nohost do
        [{Cachex, name: Supavisor.Cache} | children]
      else
        children
      end

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Supavisor.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    SupavisorWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
