defmodule Supavisor.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    :ranch.start_listener(
      :pg_proxy,
      :ranch_tcp,
      # :ranch_ssl,
      %{socket_opts: [port: Application.get_env(:supavisor, :proxy_port)]},
      Supavisor.ClientHandler,
      []
    )

    :syn.add_node_to_scopes([:tenants])

    Registry.start_link(
      keys: :unique,
      name: Supavisor.Registry.Tenants
    )

    children = [
      # Start the Ecto repository
      Supavisor.Repo,
      # Start the Telemetry supervisor
      SupavisorWeb.Telemetry,
      # Start the PubSub system
      {Phoenix.PubSub, name: Supavisor.PubSub},
      # Start the Endpoint (http/https)
      SupavisorWeb.Endpoint,
      {
        PartitionSupervisor,
        child_spec: DynamicSupervisor, strategy: :one_for_one, name: Supavisor.DynamicSupervisor
      },
      Supavisor.Vault
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
