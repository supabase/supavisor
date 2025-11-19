defmodule Supavisor.TenantSupervisor do
  @moduledoc false
  use Supervisor

  require Logger
  alias Supavisor.Manager
  alias Supavisor.SecretChecker
  alias Supavisor.Terminator

  def start_link(args) do
    meta = Supavisor.get_local_server(args.id)
    name = {:via, :syn, {:tenants, args.id, meta}}
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
          start:
            {:poolboy, :start_link, [pool_spec(id, e.replica_type, e.pool_size), %{id: args.id}]},
          restart: :temporary
        }
      end)

    manager_args = %{id: args.id, secrets: args.secrets, log_level: args.log_level}
    secret_checker_args = %{id: args.id}
    cache_args = %{id: args.id}
    terminator_args = %{id: args.id}

    children =
      [
        {Supavisor.TenantCache, cache_args},
        {Manager, manager_args},
        {SecretChecker, secret_checker_args}
        | pools
      ] ++ [{Terminator, terminator_args}]

    map_id = %{user: user, mode: mode, type: type, db_name: db_name, search_path: search_path}
    Registry.register(Supavisor.Registry.TenantSups, tenant, map_id)

    Supervisor.init(children,
      strategy: :one_for_one,
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

  @spec pool_spec(tuple, atom, integer) :: Keyword.t()
  defp pool_spec(id, replica_type, pool_size) do
    {size, overflow} = {1, pool_size}

    [
      name: {:via, Registry, {Supavisor.Registry.Tenants, id, replica_type}},
      worker_module: Supavisor.DbHandler,
      size: size,
      max_overflow: overflow,
      strategy: :lifo,
      idle_timeout: :timer.minutes(5)
    ]
  end
end
