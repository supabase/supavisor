defmodule Supavisor do
  @moduledoc false
  require Logger
  import Cachex.Spec
  alias Supavisor.Helpers, as: H
  alias Supavisor.Tenants, as: T
  alias Supavisor.Manager

  @type sock :: tcp_sock() | ssl_sock()
  @type ssl_sock :: {:ssl, :ssl.sslsocket()}
  @type tcp_sock :: {:gen_tcp, :gen_tcp.socket()}
  @type workers :: %{manager: pid, pool: pid}
  @type secrets :: {:password | :auth_query, fun()}
  @type mode :: :transaction | :session | :native
  @type id :: {{:single | :cluster, String.t()}, String.t(), mode, String.t()}
  @type subscribe_opts :: %{workers: workers, ps: list, idle_timeout: integer}

  @registry Supavisor.Registry.Tenants

  @spec start_dist(id, secrets, keyword()) :: {:ok, pid()} | {:error, any()}
  def start_dist(id, secrets, options \\ []) do
    options = Keyword.validate!(options, log_level: nil, force_node: false)
    log_level = Keyword.fetch!(options, :log_level)
    force_node = Keyword.fetch!(options, :force_node)

    case get_global_sup(id) do
      nil ->
        node = if force_node, do: force_node, else: determine_node(id)

        if node == node() do
          Logger.debug("Starting local pool for #{inspect(id)}")
          start_local_pool(id, secrets, log_level)
        else
          Logger.debug("Starting remote pool for #{inspect(id)}")
          H.rpc(node, __MODULE__, :start_local_pool, [id, secrets, log_level])
        end

      pid ->
        {:ok, pid}
    end
  end

  @spec start(id, secrets) :: {:ok, pid} | {:error, any}
  def start(id, secrets) do
    case get_global_sup(id) do
      nil ->
        start_local_pool(id, secrets)

      pid ->
        {:ok, pid}
    end
  end

  @spec stop(id) :: :ok | {:error, :tenant_not_found}
  def stop(id) do
    case get_global_sup(id) do
      nil -> {:error, :tenant_not_found}
      pid -> Supervisor.stop(pid)
    end
  end

  @spec get_local_workers(id) :: {:ok, workers} | {:error, :worker_not_found}
  def get_local_workers(id) do
    workers = %{
      manager: get_local_manager(id),
      pool: get_local_pool(id)
    }

    if Map.values(workers) |> Enum.member?(nil) do
      Logger.error("Could not get workers for tenant #{inspect(id)}")
      {:error, :worker_not_found}
    else
      {:ok, workers}
    end
  end

  @spec subscribe_local(pid, id) :: {:ok, subscribe_opts} | {:error, any()}
  def(subscribe_local(pid, id)) do
    with {:ok, workers} <- get_local_workers(id),
         {:ok, ps, idle_timeout} <- Manager.subscribe(workers.manager, pid) do
      {:ok, %{workers: workers, ps: ps, idle_timeout: idle_timeout}}
    else
      error ->
        error
    end
  end

  @spec subscribe(pid, id, pid) :: {:ok, subscribe_opts} | {:error, any()}
  def subscribe(sup, id, pid \\ self()) do
    dest_node = node(sup)

    if node() == dest_node do
      subscribe_local(pid, id)
    else
      try do
        # TODO: tests for different cases
        :erpc.call(dest_node, __MODULE__, :subscribe_local, [pid, id], 15_000)
        |> case do
          {:EXIT, _} = badrpc -> {:error, {:badrpc, badrpc}}
          result -> result
        end
      catch
        kind, reason -> {:error, {:badrpc, {kind, reason}}}
      end
    end
  end

  @spec get_global_sup(id) :: pid | nil
  def get_global_sup(id) do
    case :syn.whereis_name({:tenants, id}) do
      :undefined -> nil
      pid -> pid
    end
  end

  @doc """
  During netsplits, or due to certain internal conflicts, :syn may store inconsistent data across the cluster.
  This function terminates all connection trees related to a specific tenant.
  """
  @spec dirty_terminate(String.t(), pos_integer()) :: map()
  def dirty_terminate(tenant, timeout \\ 15_000) do
    Registry.lookup(Supavisor.Registry.TenantSups, tenant)
    |> Enum.reduce(%{}, fn {pid, %{user: user, mode: _mode}}, acc ->
      stop =
        try do
          Supervisor.stop(pid, :shutdown, timeout)
        catch
          error, reason -> {:error, {error, reason}}
        end

      resp = %{
        stop: stop,
        cache: del_all_cache(tenant, user)
      }

      Map.put(acc, user, resp)
    end)
  end

  def terminate_global(tenant) do
    [node() | Node.list()]
    |> :erpc.multicall(Supavisor, :dirty_terminate, [tenant], 60_000)
  end

  @spec del_all_cache(String.t(), String.t()) :: [map()]
  def del_all_cache(tenant, user) do
    Logger.info("Deleting all cache for tenant #{tenant} and user #{user}")
    {:ok, keys} = Cachex.keys(Supavisor.Cache)

    del = fn key, acc ->
      result = Cachex.del(Supavisor.Cache, key)
      [%{inspect(key) => inspect(result)} | acc]
    end

    Enum.reduce(keys, [], fn
      {:metrics, ^tenant} = key, acc -> del.(key, acc)
      {:secrets, ^tenant, ^user} = key, acc -> del.(key, acc)
      {:user_cache, _, ^user, ^tenant, _} = key, acc -> del.(key, acc)
      {:tenant_cache, ^tenant, _} = key, acc -> del.(key, acc)
      _, acc -> acc
    end)
  end

  @spec del_all_cache(String.t()) :: [map()]
  def del_all_cache(tenant) do
    Logger.info("Deleting all cache for tenant #{tenant}")

    del = fn key, acc ->
      result = Cachex.del(Supavisor.Cache, key)
      [%{inspect(key) => inspect(result)} | acc]
    end

    Supavisor.Cache
    |> Cachex.stream!()
    |> Enum.reduce([], fn entry(key: key), acc ->
      case key do
        {:metrics, ^tenant} -> del.(key, acc)
        {:secrets, ^tenant, _} -> del.(key, acc)
        {:user_cache, _, _, ^tenant, _} -> del.(key, acc)
        {:tenant_cache, ^tenant, _} -> del.(key, acc)
        _ -> acc
      end
    end)
  end

  @spec del_all_cache_dist(String.t(), pos_integer()) :: [map()]
  def del_all_cache_dist(tenant, timeout \\ 15_000) do
    Logger.info("Deleting all dist cache for tenant #{tenant}")

    for node <- [node() | Node.list()] do
      %{to_string(node) => :erpc.call(node, Supavisor, :del_all_cache, [tenant], timeout)}
    end
  end

  @spec get_local_pool(id) :: map | pid | nil
  def get_local_pool(id) do
    match = {{:pool, :_, :_, id}, :"$2", :"$3"}
    body = [{{:"$2", :"$3"}}]

    case Registry.select(@registry, [{match, [], body}]) do
      [{pool, _}] ->
        pool

      [_ | _] = pools ->
        # transform [{pid1, :read}, {pid2, :read}, {pid3, :write}]
        # to %{read: [pid1, pid2], write: [pid3]}
        Enum.group_by(pools, &elem(&1, 1), &elem(&1, 0))

      _ ->
        nil
    end
  end

  @spec get_local_manager(id) :: pid | nil
  def get_local_manager(id) do
    case Registry.lookup(@registry, {:manager, id}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  @spec id({:single | :cluster, String.t()}, String.t(), mode, mode, String.t()) :: id
  def id(tenant, user, port_mode, user_mode, db_name) do
    # temporary hack
    mode =
      if port_mode == :transaction do
        user_mode
      else
        port_mode
      end

    {tenant, user, mode, db_name}
  end

  @spec tenant(id) :: String.t()
  def tenant({{_, tenant}, _, _, _}), do: tenant

  @spec mode(id) :: atom()
  def mode({_, _, mode, _}), do: mode

  @spec determine_node(id) :: Node.t()
  def determine_node(id) do
    tenant_id = tenant(id)
    nodes = [node() | Node.list()] |> Enum.sort()
    index = :erlang.phash2(tenant_id, length(nodes))
    Enum.at(nodes, index)
  end

  @spec start_local_pool(id, secrets, atom()) :: {:ok, pid} | {:error, any}
  def start_local_pool({{type, tenant}, _user, _mode, _db_name} = id, secrets, log_level \\ nil) do
    Logger.debug("Starting pool(s) for #{inspect(id)}")

    user = elem(secrets, 1).().alias

    case type do
      :single -> T.get_pool_config(tenant, user)
      :cluster -> T.get_cluster_config(tenant, user)
    end
    |> case do
      [_ | _] = replicas ->
        opts =
          Enum.map(replicas, fn replica ->
            case replica do
              %T.ClusterTenants{tenant: tenant, type: type} ->
                Map.put(tenant, :replica_type, type)

              %T.Tenant{} = tenant ->
                Map.put(tenant, :replica_type, :write)
            end
            |> supervisor_args(id, secrets, log_level)
          end)

        DynamicSupervisor.start_child(
          {:via, PartitionSupervisor, {Supavisor.DynamicSupervisor, id}},
          {Supavisor.TenantSupervisor, %{id: id, replicas: opts, log_level: log_level}}
        )
        |> case do
          {:error, {:already_started, pid}} -> {:ok, pid}
          resp -> resp
        end

      error ->
        Logger.error("Can't find tenant with external_id #{inspect(id)} #{inspect(error)}")

        {:error, :tenant_not_found}
    end
  end

  ## Internal functions

  defp supervisor_args(
         tenant_record,
         {tenant, user, mode, db_name} = id,
         {method, secrets},
         log_level
       ) do
    %{
      db_host: db_host,
      db_port: db_port,
      db_database: db_database,
      default_parameter_status: ps,
      ip_version: ip_ver,
      default_pool_size: def_pool_size,
      default_max_clients: def_max_clients,
      client_idle_timeout: client_idle_timeout,
      replica_type: replica_type,
      users: [
        %{
          db_user: db_user,
          db_password: db_pass,
          pool_size: pool_size,
          # mode_type: mode_type,
          max_clients: max_clients
        }
      ]
    } = tenant_record

    {pool_size, max_clients} =
      if method == :auth_query do
        {def_pool_size, def_max_clients}
      else
        {pool_size, max_clients}
      end

    auth = %{
      host: String.to_charlist(db_host),
      port: db_port,
      user: db_user,
      database: if(db_name != nil, do: db_name, else: db_database),
      password: fn -> db_pass end,
      application_name: "Supavisor",
      ip_version: H.ip_version(ip_ver, db_host),
      upstream_ssl: tenant_record.upstream_ssl,
      upstream_verify: tenant_record.upstream_verify,
      upstream_tls_ca: H.upstream_cert(tenant_record.upstream_tls_ca),
      require_user: tenant_record.require_user,
      method: method,
      secrets: secrets
    }

    %{
      id: id,
      tenant: tenant,
      replica_type: replica_type,
      user: user,
      auth: auth,
      pool_size: pool_size,
      mode: mode,
      default_parameter_status: ps,
      max_clients: max_clients,
      client_idle_timeout: client_idle_timeout,
      log_level: log_level
    }
  end

  @spec set_parameter_status(id, [{binary, binary}]) ::
          :ok | {:error, :not_found}
  def set_parameter_status(id, ps) do
    case get_local_manager(id) do
      nil -> {:error, :not_found}
      pid -> Manager.set_parameter_status(pid, ps)
    end
  end
end
