defmodule Supavisor.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application
  require Logger
  alias Supavisor.Monitoring.PromEx

  @impl true
  def start(_type, _args) do
    primary_config = :logger.get_primary_config()

    :ok =
      :logger.set_primary_config(
        :metadata,
        Enum.into(
          [region: System.get_env("REGION"), instance_id: System.get_env("INSTANCE_ID")],
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
       :transaction},
      {:pg_proxy_session, Application.get_env(:supavisor, :proxy_port_session), :session}
    ]

    for {key, port, mode} <- proxy_ports do
      :ranch.start_listener(
        key,
        :ranch_tcp,
        %{
          max_connections: String.to_integer(System.get_env("MAX_CONNECTIONS") || "25000"),
          num_acceptors: String.to_integer(System.get_env("NUM_ACCEPTORS") || "100"),
          socket_opts: [port: port, keepalive: true]
        },
        Supavisor.ClientHandler,
        %{mode: mode}
      )
      |> then(&"Proxy started #{mode} on port #{port}, result: #{inspect(&1)}")
      |> Logger.warning()
    end

    :syn.set_event_handler(Supavisor.SynHandler)
    :syn.add_node_to_scopes([:tenants])

    PromEx.set_metrics_tags()

    topologies = Application.get_env(:libcluster, :topologies) || []

    children = [
      Supavisor.ErlSysMon,
      PromEx,
      {Registry, keys: :unique, name: Supavisor.Registry.Tenants},
      {Registry, keys: :unique, name: Supavisor.Registry.ManagerTables},
      {Registry, keys: :unique, name: Supavisor.Registry.PoolPids},
      {Registry, keys: :duplicate, name: Supavisor.Registry.TenantSups},
      {Registry, keys: :duplicate, name: Supavisor.Registry.TenantClients},
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
      Supavisor.TenantsMetrics,
      # Start the Endpoint (http/https)
      SupavisorWeb.Endpoint
    ]

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
