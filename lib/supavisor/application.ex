defmodule Supavisor.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application
  require Logger
  alias Supavisor.Monitoring.PromEx

  @impl true
  def start(_type, _args) do
    :ok =
      :gen_event.swap_sup_handler(
        :erl_signal_server,
        {:erl_signal_handler, []},
        {Supavisor.SignalHandler, []}
      )

    proxy_ports = [
      {Application.get_env(:supavisor, :proxy_port), :transaction},
      {Application.get_env(:supavisor, :proxy_port_session), :session}
    ]

    for {port, mode} <- proxy_ports do
      :ranch.start_listener(
        :pg_proxy,
        :ranch_tcp,
        %{
          max_connections: String.to_integer(System.get_env("MAX_CONNECTIONS") || "25000"),
          num_acceptors: String.to_integer(System.get_env("NUM_ACCEPTORS") || "100"),
          socket_opts: [port: port]
        },
        Supavisor.ClientHandler,
        %{def_mode_type: mode}
      )
      |> then(&"Proxy started #{mode} on port #{port}, result: #{inspect(&1)}")
      |> Logger.warning()
    end

    :syn.set_event_handler(Supavisor.SynHandler)
    :syn.add_node_to_scopes([:tenants])

    Registry.start_link(
      keys: :unique,
      name: Supavisor.Registry.Tenants
    )

    Registry.start_link(
      keys: :unique,
      name: Supavisor.Registry.ManagerTables
    )

    PromEx.set_metrics_tags()

    topologies = Application.get_env(:libcluster, :topologies) || []

    children = [
      PromEx,
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
      {Cachex, name: Supavisor.Cache},
      # Start the Endpoint (http/https)
      SupavisorWeb.Endpoint
    ]

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
