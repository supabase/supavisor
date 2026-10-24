defmodule Supavisor.Ops do
  @moduledoc """
  Operational commands exposed through the API, e.g. listing a tenant's pools
  across the cluster.
  """

  require Logger

  alias Supavisor.Manager
  alias Supavisor.Tenants

  @multicall_timeout :timer.seconds(5)
  @stop_timeout :timer.seconds(15)

  @type connection_counts :: %{idle: non_neg_integer(), checked_out: non_neg_integer()}

  @type pool_info :: %{
          id: Supavisor.id(),
          pid: pid(),
          pid_label: String.t(),
          status: :active | :shutting_down,
          node: node(),
          db_host: String.t() | nil,
          db_port: non_neg_integer() | nil,
          clients: non_neg_integer() | nil,
          db_connections: connection_counts() | nil
        }

  @doc """
  Lists a tenant's pools on every node. Nodes that fail to answer are returned
  under `:errors` instead of failing the whole listing.
  """
  @spec list_pools(String.t()) ::
          {:ok, %{pools: [pool_info()], errors: %{node() => term()}}}
          | {:error, :tenant_not_found}
  def list_pools(tenant) do
    if Tenants.tenant_exists?(tenant) do
      nodes = [node() | Node.list()]

      results =
        :erpc.multicall(nodes, __MODULE__, :list_pools_local, [tenant], @multicall_timeout)

      nodes
      |> Enum.zip(results)
      |> Enum.reduce(%{pools: [], errors: %{}}, fn
        {_node, {:ok, node_pools}}, acc ->
          %{acc | pools: acc.pools ++ node_pools}

        {node, error}, acc ->
          Logger.warning("Failed to list pools of #{tenant} on #{node}: #{inspect(error)}")
          %{acc | errors: Map.put(acc.errors, node, error)}
      end)
      |> then(&{:ok, &1})
    else
      {:error, :tenant_not_found}
    end
  end

  @doc """
  Lists a tenant's pools on this node. Values that can't be read, e.g. of a pool
  that is shutting down, are `nil`.
  """
  @spec list_pools_local(String.t()) :: [pool_info()]
  def list_pools_local(tenant) do
    Supavisor.Registry.TenantSups
    |> Registry.lookup(tenant)
    |> Enum.map(fn {sup, id} ->
      {db_host, db_port} = db_host_port(id)

      %{
        id: id,
        pid: sup,
        # Built on the pool's node: how a remote pid prints depends on the node printing it.
        pid_label: inspect(sup),
        status: status(id, sup),
        node: node(sup),
        db_host: db_host,
        db_port: db_port,
        clients: Manager.client_count(id),
        db_connections: connection_counts(id)
      }
    end)
  end

  # A pool's Terminator unregisters it from :syn as soon as it starts shutting down,
  # so a new pool for the same id can start on another node while this one drains.
  @spec status(Supavisor.id(), pid()) :: :active | :shutting_down
  defp status(id, sup) do
    if Supavisor.get_global_sup(id) == sup, do: :active, else: :shutting_down
  end

  @doc """
  Gracefully stops one of a tenant's pools, given its supervisor's pid. `timeout`
  only bounds the wait: past it, `{:ok, :stopping}` is returned and the pool keeps
  shutting down.
  """
  @spec stop_pool(String.t(), pid(), pos_integer()) ::
          {:ok, :stopped | :stopping} | {:error, :not_found | :node_unreachable}
  def stop_pool(tenant, sup, timeout \\ @stop_timeout) do
    :erpc.call(
      node(sup),
      __MODULE__,
      :stop_pool_local,
      [tenant, sup, timeout],
      timeout + @multicall_timeout
    )
  catch
    :error, {:erpc, :noconnection} = reason ->
      Logger.warning("Failed to stop pool of #{tenant} on #{node(sup)}: #{inspect(reason)}")
      {:error, :node_unreachable}
  end

  @doc """
  Stops one of a tenant's pools on this node. Only a pid registered as one of
  `tenant`'s pools is stopped, so a stale pid can't hit another process.
  """
  @spec stop_pool_local(String.t(), pid(), pos_integer()) ::
          {:ok, :stopped | :stopping} | {:error, :not_found}
  def stop_pool_local(tenant, sup, timeout) do
    case Registry.values(Supavisor.Registry.TenantSups, tenant, sup) do
      [id] ->
        result = stop_sup(sup, timeout)
        Logger.warning("Stop pool #{Supavisor.inspect_id(id)}: #{inspect(result)}")
        result

      [] ->
        {:error, :not_found}
    end
  end

  @spec stop_sup(pid(), timeout()) :: {:ok, :stopped | :stopping}
  defp stop_sup(sup, timeout) do
    :ok = Supervisor.stop(sup, :shutdown, timeout)
    {:ok, :stopped}
  catch
    # Already gone, e.g. stopped concurrently.
    :exit, {:noproc, _} -> {:ok, :stopped}
    # It was already shutting down, so it never answered our request: the request
    # failed with its exit reason (whatever stopped it), which only happens once it
    # has exited.
    :exit, {{_exit_reason, {:sys, :terminate, _}}, _} -> {:ok, :stopped}
    :exit, {:timeout, _} -> {:ok, :stopping}
  end

  # The manager can exit between the lookup and the call, e.g. while the pool stops.
  @spec db_host_port(Supavisor.id()) :: {String.t() | nil, non_neg_integer() | nil}
  defp db_host_port(id) do
    case Supavisor.get_local_manager(id) do
      nil ->
        {nil, nil}

      pid ->
        %{host: host, port: port} = Manager.get_config(pid).connection_params
        {to_string(host), port}
    end
  catch
    :exit, _ -> {nil, nil}
  end

  # Summed across the replicas of a `:cluster` pool.
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

  # A `:cluster` pool has one poolboy per replica.
  @spec pool_pids(Supavisor.id()) :: [pid()]
  defp pool_pids(id) do
    case Supavisor.get_local_pool(id) do
      nil -> []
      pid when is_pid(pid) -> [pid]
      %{} = replicas -> replicas |> Map.values() |> List.flatten()
    end
  end

  @spec pool_status(pid()) :: {:ok, non_neg_integer(), non_neg_integer()} | :error
  defp pool_status(pid) do
    {_state, idle, _overflow_in_use, checked_out} = :poolboy.status(pid)
    {:ok, idle, checked_out}
  catch
    :exit, _ -> :error
  end
end
