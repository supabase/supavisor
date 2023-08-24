defmodule Supavisor.TenantSupervisor do
  @moduledoc false
  use Supervisor

  alias Supavisor.Manager

  def start_link(args) do
    name = {:via, :syn, {:tenants, args.id}}
    Supervisor.start_link(__MODULE__, args, name: name)
  end

  @impl true
  def init(%{pool_size: pool_size} = args) do
    {size, overflow} =
      case args.mode do
        :session -> {1, pool_size}
        :transaction -> {pool_size, 0}
      end

    pool_spec = [
      name: {:via, Registry, {Supavisor.Registry.Tenants, {:pool, args.id}}},
      worker_module: Supavisor.DbHandler,
      size: size,
      max_overflow: overflow
    ]

    children = [
      %{
        id: {:pool, args.id},
        start: {:poolboy, :start_link, [pool_spec, args]},
        restart: :transient
      },
      {Manager, args}
    ]

    {tenant, user, mode} = args.id
    map_id = %{user: user, mode: mode}
    Registry.register(Supavisor.Registry.TenantSups, tenant, map_id)
    Supervisor.init(children, strategy: :one_for_all, max_restarts: 10, max_seconds: 60)
  end

  def child_spec(args) do
    %{
      id: args.id,
      start: {__MODULE__, :start_link, [args]},
      restart: :transient
    }
  end
end
