defmodule Supavisor.Ops do
  @moduledoc """
  Operator / maintenance operations over a tenant's pools.

  Functions suffixed with `_local` act on the pools of the current node only.
  Their siblings fan out to the whole cluster via `:erpc`, tolerating nodes that
  fail to answer (their errors are returned, keyed by node, rather than raised).

  A "pool" here is one `Supavisor.TenantSupervisor` (one per `Supavisor.id`): its
  `Supavisor.Manager`, `Supavisor.SecretChecker`, the poolboy connection pool and
  its `Supavisor.DbHandler` backends.
  """

  require Supavisor

  alias Supavisor.Manager

  @multicall_timeout :timer.seconds(5)

  @type connection_counts :: %{idle: non_neg_integer(), checked_out: non_neg_integer()}

  @type pool_info :: %{
          id: Supavisor.id(),
          node: node(),
          host: String.t() | nil,
          port: non_neg_integer() | nil,
          clients: non_neg_integer() | nil,
          connections: connection_counts() | nil
        }

  @doc """
  Lists a tenant's pools across the whole cluster.

  Each node reports the pools it owns via `list_pools_local/1`. A node that fails
  to answer is recorded under `:errors` keyed by node, so one bad node does not
  hide the rest.
  """
  @spec list_pools(String.t()) :: %{pools: [pool_info()], errors: %{node() => term()}}
  def list_pools(tenant) do
    nodes = [node() | Node.list()]
    results = :erpc.multicall(nodes, __MODULE__, :list_pools_local, [tenant], @multicall_timeout)

    nodes
    |> Enum.zip(results)
    |> Enum.reduce(%{pools: [], errors: %{}}, fn
      {_node, {:ok, node_pools}}, acc -> %{acc | pools: acc.pools ++ node_pools}
      {node, error}, acc -> %{acc | errors: Map.put(acc.errors, node, error)}
    end)
  end

  @doc """
  Lists the pools a tenant has on the current node.

  Reads the local `Supavisor.Registry.TenantSups` registry. Per-pool lookups that
  fail (a manager mid-shutdown, a busy poolboy) degrade to `nil` counts rather
  than failing the whole listing.
  """
  @spec list_pools_local(String.t()) :: [pool_info()]
  def list_pools_local(tenant) do
    Supavisor.Registry.TenantSups
    |> Registry.lookup(tenant)
    |> Enum.map(fn {sup, id} ->
      {host, port} = host_port(id)

      %{
        id: id,
        node: node(sup),
        host: host,
        port: port,
        clients: Manager.client_count(id),
        connections: connection_counts(id)
      }
    end)
  end

  # The manager's config carries the upstream host/port. Match on the manager's
  # presence instead of rescuing a raise; the narrow `catch` only covers the race
  # where the manager dies between the lookup and the config call (e.g. mid-kill).
  @spec host_port(Supavisor.id()) :: {String.t() | nil, non_neg_integer() | nil}
  defp host_port(id) do
    case Supavisor.get_local_manager(id) do
      nil ->
        {nil, nil}

      _pid ->
        %{host: host, port: port} = Manager.get_config(id).connection_params
        {host && to_string(host), port}
    end
  catch
    :exit, _ -> {nil, nil}
  end

  # Open backend connections (idle + checked_out) from poolboy `:status`, summed
  # across replica pools. `nil` when the pool has no live poolboy yet.
  @spec connection_counts(Supavisor.id()) :: connection_counts() | nil
  defp connection_counts(id) do
    case pool_pids(id) do
      [] ->
        nil

      pids ->
        Enum.reduce(pids, %{idle: 0, checked_out: 0}, fn pid, acc ->
          case pool_status(pid) do
            {:ok, idle, checked_out} ->
              %{idle: acc.idle + idle, checked_out: acc.checked_out + checked_out}

            :error ->
              acc
          end
        end)
    end
  end

  # `get_local_pool/1` returns a single poolboy pid for a `:single` pool, or a
  # `%{read: [...], write: [...]}` map for a `:cluster` pool (one poolboy per
  # replica). Flatten both to a list of poolboy pids.
  @spec pool_pids(Supavisor.id()) :: [pid()]
  defp pool_pids(id) do
    case Supavisor.get_local_pool(id) do
      nil -> []
      pid when is_pid(pid) -> [pid]
      %{} = replicas -> replicas |> Map.values() |> List.flatten()
    end
  end

  # `:poolboy.status/1` returns `{state, idle, overflow_in_use, total_checked_out}`.
  @spec pool_status(pid()) :: {:ok, non_neg_integer(), non_neg_integer()} | :error
  defp pool_status(pid) do
    {_state, idle, _overflow_in_use, checked_out} = :poolboy.status(pid)
    {:ok, idle, checked_out}
  catch
    :exit, _ -> :error
  end
end
