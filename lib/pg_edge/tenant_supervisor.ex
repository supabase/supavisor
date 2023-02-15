defmodule PgEdge.TenantSupervisor do
  @moduledoc false
  use Supervisor

  alias PgEdge.Manager

  @spec start_link(atom | %{:tenant => any, optional(any) => any}) ::
          :ignore | {:error, any} | {:ok, pid}
  def start_link(args) do
    name = {:via, :syn, PgEdge.supervisor_name(args.tenant)}
    Supervisor.start_link(__MODULE__, args, name: name)
  end

  @impl true
  def init(%{tenant: tenant, pool_size: pool_size} = args) do
    pool_spec = [
      name: {:via, :syn, {:pool, tenant}},
      worker_module: PgEdge.DbHandler,
      size: pool_size,
      max_overflow: 0
    ]

    children = [
      %{
        id: {:pool, args.tenant},
        start: {:poolboy, :start_link, [pool_spec, args]},
        restart: :transient
      },
      {Manager, args}
    ]

    Supervisor.init(children, strategy: :one_for_all, max_restarts: 10, max_seconds: 60)
  end

  def child_spec(args) do
    %{
      id: args.tenant,
      start: {__MODULE__, :start_link, [args]},
      restart: :transient
    }
  end
end
