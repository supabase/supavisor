defmodule PgEdge.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the Ecto repository
      # PgEdge.Repo,
      # Start the Telemetry supervisor
      PgEdgeWeb.Telemetry,
      # Start the PubSub system
      {Phoenix.PubSub, name: PgEdge.PubSub},
      # Start the Endpoint (http/https)
      PgEdgeWeb.Endpoint
      # Start a worker by calling: PgEdge.Worker.start_link(arg)
      # {PgEdge.Worker, arg}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: PgEdge.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    PgEdgeWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
