defmodule Supavisor.TenantSupervisor do
  @moduledoc false
  use Supervisor

  require Logger
  alias Supavisor.Manager
  alias Supavisor.SecretChecker

  def start_link(%{replicas: [%{mode: mode} = single]} = args)
      when mode in [:transaction, :session] do
    {:ok, meta} = Supavisor.start_local_server(single)
    Logger.info("Starting ranch instance #{inspect(meta)} for #{inspect(args.id)}")
    name = {:via, :syn, {:tenants, args.id, meta}}
    Supervisor.start_link(__MODULE__, args, name: name)
  end

  def start_link(args) do
    name = {:via, :syn, {:tenants, args.id}}
    Supervisor.start_link(__MODULE__, args, name: name)
  end

  @impl true
  def init(%{replicas: replicas} = args) do
    {{type, tenant}, user, mode, db_name, search_path} = args.id

    pools =
      replicas
      |> Enum.with_index()
      |> Enum.map(fn {e, i} ->
        id = {:pool, e.replica_type, i, args.id}

        %{
          id: {:pool, id},
          start: {:poolboy, :start_link, [pool_spec(id, e), e]},
          restart: :temporary
        }
      end)

    children = [{Manager, args}, {SecretChecker, args} | pools]

    map_id = %{user: user, mode: mode, type: type, db_name: db_name, search_path: search_path}
    Registry.register(Supavisor.Registry.TenantSups, tenant, map_id)

    Supervisor.init(children,
      strategy: :one_for_all,
      max_restarts: 10,
      max_seconds: 60
    )
  end

  def child_spec(args) do
    %{
      id: args.id,
      start: {__MODULE__, :start_link, [args]},
      restart: :transient
    }
  end

  @spec pool_spec(tuple, map) :: Keyword.t()
  defp pool_spec(id, args) do
    {size, overflow} = {1, args.pool_size}

    [
      name: {:via, Registry, {Supavisor.Registry.Tenants, id, args.replica_type}},
      worker_module: Supavisor.DbHandler,
      size: size,
      max_overflow: overflow,
      strategy: :lifo,
      idle_timeout: :timer.minutes(5)
    ]
  end
end
