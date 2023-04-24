defmodule Supavisor.TenantSupervisor do
  @moduledoc false
  use Supervisor

  alias Supavisor.Manager

  def start_link(args) do
    name = {:via, :syn, {:tenants, {args.tenant, args.user_alias}}}
    Supervisor.start_link(__MODULE__, args, name: name)
  end

  @impl true
  def init(%{tenant: tenant, user_alias: user_alias, pool_size: pool_size} = args) do
    id = {tenant, user_alias}

    pool_spec = [
      name: {:via, Registry, {Supavisor.Registry.Tenants, {:pool, id}}},
      worker_module: Supavisor.DbHandler,
      size: pool_size,
      max_overflow: 0
    ]

    children = [
      %{
        id: {:pool, id},
        start: {:poolboy, :start_link, [pool_spec, args]},
        restart: :transient
      },
      {Manager, args}
    ]

    Supervisor.init(children, strategy: :one_for_all, max_restarts: 10, max_seconds: 60)
  end

  def child_spec(args) do
    %{
      id: {args.tenant, args.user_alias},
      start: {__MODULE__, :start_link, [args]},
      restart: :transient
    }
  end
end
