defmodule PgEdge.Application do
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
      %{socket_opts: [port: Application.get_env(:pg_edge, :proxy_port)]},
      PgEdge.ClientHandler,
      []
    )

    children = [
      # Start the Ecto repository
      # PgEdge.Repo,
      # Start the Telemetry supervisor
      PgEdgeWeb.Telemetry,
      # Start the PubSub system
      {Phoenix.PubSub, name: PgEdge.PubSub},
      # Start the Endpoint (http/https)
      PgEdgeWeb.Endpoint,
      :poolboy.child_spec(:worker, dev_pool())
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

  defp dev_pool do
    [
      name: {:local, :db_sess},
      worker_module: PgEdge.DbHandler,
      size: Application.get_env(:pg_edge, :pool_size),
      max_overflow: 0
    ]
  end
end
