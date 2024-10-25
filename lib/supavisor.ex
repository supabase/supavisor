defmodule Supavisor do
  @moduledoc false

  require Logger

  alias Supavisor.{
    Helpers,
    Manager,
    Tenants
  }

  @type sock :: tcp_sock() | ssl_sock()
  @type ssl_sock :: {:ssl, :ssl.sslsocket()}
  @type tcp_sock :: {:gen_tcp, :gen_tcp.socket()}
  @type workers :: %{manager: pid, pool: pid}
  @type secrets :: {:password | :auth_query, fun()}
  @type mode :: :transaction | :session | :native | :proxy
  @type id :: {{:single | :cluster, String.t()}, String.t(), mode, String.t(), String.t() | nil}
  @type subscribe_opts :: %{workers: workers, ps: list, idle_timeout: integer}

  @registry Supavisor.Registry.Tenants
  @max_pools Application.compile_env(:supavisor, :max_pools, 20)

  @spec start_dist(id, secrets, keyword()) :: {:ok, pid()} | {:error, any()}
  def start_dist(id, secrets, options \\ []) do
    options =
      Keyword.validate!(options, log_level: nil, force_node: false, availability_zone: nil)

    log_level = Keyword.fetch!(options, :log_level)
    force_node = Keyword.fetch!(options, :force_node)
    availability_zone = Keyword.fetch!(options, :availability_zone)

    case get_global_sup(id) do
      nil ->
        node = if force_node, do: force_node, else: determine_node(id, availability_zone)

        if node == node() do
          Logger.debug("Starting local pool for #{inspect(id)}")
          try_start_local_pool(id, secrets, log_level)
        else
          Logger.debug("Starting remote pool for #{inspect(id)}")
          Helpers.rpc(node, __MODULE__, :try_start_local_pool, [id, secrets, log_level])
        end

      pid ->
        {:ok, pid}
    end
  end

  @spec start(id, secrets) :: {:ok, pid} | {:error, any}
  def start(id, secrets) do
    case get_global_sup(id) do
      nil ->
        try_start_local_pool(id, secrets, nil)

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
  def subscribe_local(pid, id) do
    with {:ok, workers} <- get_local_workers(id),
         {:ok, ps, idle_timeout} <- Manager.subscribe(workers.manager, pid) do
      {:ok, %{workers: workers, ps: ps, idle_timeout: idle_timeout}}
    end
  end

  @spec subscribe(pid, id, pid) :: {:ok, subscribe_opts} | {:error, any()}
  def subscribe(sup, id, pid \\ self()) do
    dest_node = node(sup)

    if node() == dest_node do
      subscribe_local(pid, id)
    else
      Helpers.rpc(dest_node, __MODULE__, :subscribe_local, [pid, id], 15_000)
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
      {:pool_config_cache, ^tenant, ^user} = key, acc -> del.(key, acc)
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

    :ets.foldl(
      fn
        {:entry, key, _, _, _result}, acc ->
          case key do
            {:metrics, ^tenant} -> del.(key, acc)
            {:secrets, ^tenant, _} -> del.(key, acc)
            {:user_cache, _, _, ^tenant, _} -> del.(key, acc)
            {:tenant_cache, ^tenant, _} -> del.(key, acc)
            {:pool_config_cache, ^tenant, _} -> del.(key, acc)
            _ -> acc
          end

        other, acc ->
          Logger.error("Unknown key: #{inspect(other)}")
          acc
      end,
      [],
      Supavisor.Cache
    )
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

  @spec id({:single | :cluster, String.t()}, String.t(), mode, mode, String.t(), String.t() | nil) ::
          id
  def id(tenant, user, port_mode, user_mode, db_name, search_path) do
    # temporary hack
    mode =
      if port_mode == :transaction do
        user_mode
      else
        port_mode
      end

    {tenant, user, mode, db_name, search_path}
  end

  @spec tenant(id) :: String.t()
  def tenant({{_, tenant}, _, _, _, _}), do: tenant

  @spec mode(id) :: atom()
  def mode({_, _, mode, _, _}), do: mode

  @spec search_path(id) :: String.t() | nil
  def search_path({_, _, _, _, search_path}), do: search_path

  @spec determine_node(id, String.t() | nil) :: Node.t()
  def determine_node(id, availability_zone) do
    tenant_id = tenant(id)

    # If the AWS zone group is empty, we will use all nodes.
    # If the AWS zone group exists with the same zone, we will use nodes from this group.
    #   :syn.members(:availability_zone, "1c")
    #   [{#PID<0.381.0>, [node: :"node1@127.0.0.1"]}]
    nodes =
      with zone when is_binary(zone) <- availability_zone,
           zone_nodes when zone_nodes != [] <- :syn.members(:availability_zone, zone) do
        zone_nodes
        |> Enum.map(fn {_, [node: node]} -> node end)
      else
        _ -> [node() | Node.list()]
      end

    index = :erlang.phash2(tenant_id, length(nodes))

    nodes
    |> Enum.sort()
    |> Enum.at(index)
  end

  @spec try_start_local_pool(id, secrets, atom()) :: {:ok, pid} | {:error, any}
  def try_start_local_pool(id, secrets, log_level) do
    if count_pools(tenant(id)) < @max_pools,
      do: start_local_pool(id, secrets, log_level),
      else: {:error, :max_pools_reached}
  end

  @spec start_local_pool(id, secrets, atom()) :: {:ok, pid} | {:error, any}
  def start_local_pool(
        {{type, tenant}, _user, _mode, _db_name, _search_path} = id,
        secrets,
        log_level \\ nil
      ) do
    Logger.info("Starting pool(s) for #{inspect(id)}")

    user = elem(secrets, 1).().alias

    case type do
      :single -> Tenants.get_pool_config_cache(tenant, user)
      :cluster -> Tenants.get_cluster_config(tenant, user)
    end
    |> case do
      [_ | _] = replicas ->
        opts =
          Enum.map(replicas, fn replica ->
            case replica do
              %Tenants.ClusterTenants{tenant: tenant, type: type} ->
                Map.put(tenant, :replica_type, type)

              %Tenants.Tenant{} = tenant ->
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
         {tenant, user, mode, db_name, _search_path} = id,
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
      sni_hostname: sni_hostname,
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
      sni_hostname: if(sni_hostname != nil, do: to_charlist(sni_hostname)),
      port: db_port,
      user: db_user,
      database: if(db_name != nil, do: db_name, else: db_database),
      password: fn -> db_pass end,
      application_name: "Supavisor",
      ip_version: Helpers.ip_version(ip_ver, db_host),
      upstream_ssl: tenant_record.upstream_ssl,
      upstream_verify: tenant_record.upstream_verify,
      upstream_tls_ca: Helpers.upstream_cert(tenant_record.upstream_tls_ca),
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

  @spec get_pool_ranch(id) :: {:ok, map()} | {:error, :not_found}
  def get_pool_ranch(id) do
    case :syn.lookup(:tenants, id) do
      {_sup_pid, %{port: _port, host: _host} = meta} -> {:ok, meta}
      _ -> {:error, :not_found}
    end
  end

  @spec start_local_server(map()) :: {:ok, map()} | {:error, any()}
  def start_local_server(%{max_clients: max_clients} = args) do
    # max_clients=-1 is used for testing the maximum allowed clients in ProxyTest
    {acceptors, max_clients} =
      if max_clients > 0,
        do: {ceil(max_clients / 100), max_clients},
        else: {1, 100}

    opts = %{
      max_connections: max_clients * Application.get_env(:supavisor, :local_proxy_multiplier),
      num_acceptors: max(acceptors, 10),
      socket_opts: [port: 0, keepalive: true]
    }

    handler = Supavisor.ClientHandler
    args = Map.put(args, :local, true)

    with {:ok, pid} <- :ranch.start_listener(args.id, :ranch_tcp, opts, handler, args) do
      host = Application.get_env(:supavisor, :node_host)
      {:ok, %{listener: pid, host: host, port: :ranch.get_port(args.id)}}
    end
  end

  @spec count_pools(String.t()) :: non_neg_integer()
  def count_pools(tenant),
    do: Registry.count_match(Supavisor.Registry.TenantSups, tenant, :_)
end
