defmodule Supavisor.Manager do
  @moduledoc """
  The Manager is responsible for managing the config and parameter status for a pool
  """

  use GenServer, restart: :transient
  require Logger

  alias Supavisor.Protocol.Server
  alias Supavisor.Tenants
  alias Supavisor.Helpers

  @check_timeout 120_000

  @doc """
  Starts the pool manager
  """
  def start_link(args) do
    name = {:via, Registry, {Supavisor.Registry.Tenants, {:manager, args.id}}}

    GenServer.start_link(__MODULE__, args, name: name)
  end

  @doc """
  Subscribes to a pool

  Upon subscription, a client "joins" a pool. From this point, it's an active connection and
  it may receive updates destined to the pool.
  """
  @spec subscribe(pid, pid) :: {:ok, iodata() | [], integer} | {:error, :max_clients_reached}
  def subscribe(manager, pid) do
    GenServer.call(manager, {:subscribe, pid})
  end

  @doc """
  Updates parameter status for the pool

  Sends the parameter status update to all subscribed client handlers.
  """
  @spec set_parameter_status(pid, map) :: :ok
  def set_parameter_status(manager, ps) do
    GenServer.call(manager, {:set_parameter_status, ps})
  end

  @doc """
  Get the current parameter status for a pool
  """
  @spec get_parameter_status(pid) :: iodata() | []
  def get_parameter_status(manager) do
    GenServer.call(manager, :get_parameter_status)
  end

  @doc """
  Get the current auth config for a pool
  """
  @spec get_auth(pid | Supavisor.id()) :: map()
  def get_auth(manager_or_id) do
    manager = resolve_manager(manager_or_id)
    GenServer.call(manager, :get_auth)
  end

  @doc """
  Get the current config for a pool
  """
  @spec get_config(pid | Supavisor.id()) :: map()
  def get_config(manager_or_id) do
    manager = resolve_manager(manager_or_id)
    GenServer.call(manager, :get_config)
  end

  @doc """
  Terminates the pool and notifies all subscribed clients
  """
  @spec terminate_pool(pid | Supavisor.id(), map()) :: :ok
  def terminate_pool(manager_or_id, error) do
    manager = resolve_manager(manager_or_id)
    GenServer.cast(manager, {:terminate_pool, error})
  end

  # Helper to resolve manager PID from either PID or ID
  defp resolve_manager(pid) when is_pid(pid), do: pid

  defp resolve_manager(id) do
    case Supavisor.get_local_manager(id) do
      nil -> raise "Manager not found for pool #{inspect(id)}"
      pid -> pid
    end
  end

  ## Callbacks

  @impl true
  def init(args) do
    Helpers.set_log_level(args.log_level)
    tid = :ets.new(__MODULE__, [:protected])

    {{type, tenant}, _user, mode, db_name, _search_path} = args.id
    {method, secrets} = args.secrets

    # Fetch tenant configuration from database/cache
    secrets_map = secrets.()
    user = secrets_map[:alias] || secrets_map[:user]

    replicas =
      case type do
        :single -> Tenants.get_pool_config_cache(tenant, user)
        :cluster -> Tenants.get_cluster_config(tenant, user)
      end

    # Get the write replica configuration (or first if no write exists)
    tenant_record =
      case Enum.find(replicas, fn e -> Map.get(e, :replica_type) == :write end) do
        %Tenants.ClusterTenants{tenant: t} -> t
        %Tenants.Tenant{} = t -> t
        nil -> List.first(replicas)
      end

    # Extract configuration from tenant record
    %{
      db_host: db_host,
      db_port: db_port,
      db_database: db_database,
      auth_query: auth_query,
      default_parameter_status: ps,
      ip_version: ip_ver,
      default_pool_size: def_pool_size,
      default_max_clients: def_max_clients,
      client_idle_timeout: client_idle_timeout,
      sni_hostname: sni_hostname,
      feature_flags: feature_flags,
      users: [
        %{
          db_user: db_user,
          db_password: db_pass,
          pool_size: pool_size,
          db_user_alias: alias,
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

    # Build auth configuration
    auth = %{
      host: String.to_charlist(db_host),
      sni_hostname: if(sni_hostname != nil, do: to_charlist(sni_hostname)),
      port: db_port,
      user: db_user,
      alias: alias,
      auth_query: auth_query,
      database: if(db_name != nil, do: db_name, else: db_database),
      password: fn -> db_pass end,
      application_name: "Supavisor",
      ip_version: Helpers.ip_version(ip_ver, db_host),
      upstream_ssl: tenant_record.upstream_ssl,
      upstream_verify: tenant_record.upstream_verify,
      upstream_tls_ca: Helpers.upstream_cert(tenant_record.upstream_tls_ca),
      require_user: tenant_record.require_user,
      method: method
    }

    replica_type = Map.get(tenant_record, :replica_type, :write)

    # Populate cache with initial secrets
    # - For :password method, always cache both validation and upstream secrets
    # - For :auth_query method, only cache both if client_key exists (SCRAM credentials)
    #   otherwise just cache validation secrets (upstream will be cached by ClientHandler)
    secrets_map = secrets.()

    if method == :password or Map.has_key?(secrets_map, :client_key) do
      Supavisor.SecretCache.put_both(tenant, user, method, secrets)
    else
      Supavisor.SecretCache.put_validation_secrets_if_missing(tenant, user, method, secrets)
    end

    state = %{
      id: args.id,
      check_ref: check_subscribers(),
      tid: tid,
      tenant: tenant,
      parameter_status: [],
      wait_ps: [],
      default_parameter_status: ps,
      max_clients: max_clients,
      idle_timeout: client_idle_timeout,
      auth: auth,
      mode: mode,
      replica_type: replica_type,
      pool_size: pool_size,
      log_level: args.log_level,
      tenant_feature_flags: feature_flags,
      terminating_error: nil
    }

    Logger.metadata(project: tenant, user: user, type: type, db_name: db_name)
    Registry.register(Supavisor.Registry.ManagerTables, args.id, tid)

    {:ok, state}
  end

  @impl true
  def handle_call({:subscribe, _pid}, _, %{terminating_error: error} = state)
      when not is_nil(error) do
    Logger.warning("Rejecting subscription to terminating pool #{inspect(state.id)}")
    {:reply, {:error, :terminating, error}, state}
  end

  def handle_call({:subscribe, pid}, _, state) do
    Logger.debug("Subscribing #{inspect(pid)} to tenant #{inspect(state.id)}")

    {reply, new_state} =
      if :ets.info(state.tid, :size) < state.max_clients or Supavisor.mode(state.id) == :session do
        :ets.insert(state.tid, {Process.monitor(pid), pid, now()})

        case state.parameter_status do
          [] ->
            {{:ok, [], state.idle_timeout}, update_in(state.wait_ps, &[pid | &1])}

          ps ->
            {{:ok, ps, state.idle_timeout}, state}
        end
      else
        {{:error, :max_clients_reached}, state}
      end

    {:reply, reply, new_state}
  end

  def handle_call({:set_parameter_status, ps}, _, %{parameter_status: []} = state) do
    encoded_ps = Server.encode_parameter_status(ps)
    maybe_update_parameter_status(state.tenant, ps, state.default_parameter_status)

    for pid <- state.wait_ps do
      send(pid, {:parameter_status, encoded_ps})
    end

    {:reply, :ok, %{state | parameter_status: encoded_ps, wait_ps: []}}
  end

  def handle_call({:set_parameter_status, _ps}, _, state) do
    {:reply, :ok, state}
  end

  def handle_call(:get_auth, _, state) do
    {:reply, state.auth, state}
  end

  def handle_call(:get_config, _, state) do
    config = %{
      id: state.id,
      auth: state.auth,
      user: elem(state.id, 1),
      tenant: {:single, state.tenant},
      mode: state.mode,
      replica_type: state.replica_type,
      log_level: state.log_level,
      tenant_feature_flags: state.tenant_feature_flags
    }

    {:reply, config, state}
  end

  def handle_call(:get_parameter_status, _, state) do
    {:reply, state.parameter_status, state}
  end

  @impl true
  def handle_cast({:terminate_pool, error}, state) do
    Logger.warning("Terminating pool #{inspect(state.id)} due to error: #{inspect(error)}")

    client_pids = :ets.tab2list(state.tid) |> Enum.map(fn {_ref, pid, _time} -> pid end)

    error_message = Server.encode_error_message(error)

    for pid <- client_pids do
      Supavisor.ClientHandler.send_error_and_terminate(pid, error_message)
    end

    # Use a task to stop the pool supervisor to avoid deadlock, since the Manager
    # is a child of the TenantSupervisor that Supavisor.stop/1 will terminate
    Task.Supervisor.start_child(Supavisor.PoolTerminator, fn ->
      Supavisor.stop(state.id)
    end)

    {:noreply, %{state | terminating_error: error}}
  end

  @impl true
  def handle_info({:DOWN, ref, _, _, _}, state) do
    Process.cancel_timer(state.check_ref)
    :ets.take(state.tid, ref)
    {:noreply, %{state | check_ref: check_subscribers()}}
  end

  def handle_info(:check_subscribers, state) do
    Process.cancel_timer(state.check_ref)

    if :ets.info(state.tid, :size) == 0 do
      Logger.info("No subscribers for pool #{inspect(state.id)}, shutting down")
      Supavisor.stop(state.id)
      {:stop, :normal}
    else
      {:noreply, %{state | check_ref: check_subscribers()}}
    end
  end

  def handle_info(msg, state) do
    Logger.warning("Undefined msg: #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  ## Internal functions

  defp check_subscribers do
    Process.send_after(
      self(),
      :check_subscribers,
      @check_timeout
    )
  end

  defp now do
    System.system_time(:second)
  end

  @spec maybe_update_parameter_status(binary, map, map) :: :ok
  defp maybe_update_parameter_status(tenant, parameter_status, default_parameter_status) do
    parameter_status
    |> Enum.filter(fn {key, new_value} ->
      case default_parameter_status do
        %{^key => value} when value != new_value -> true
        _ -> false
      end
    end)
    |> case do
      [] ->
        :ok

      changed_parameters ->
        Logger.warning("Changed parameters: #{inspect(changed_parameters)}")

        # TODO: should we update all? Previously we only updated server version
        changed_parameters = Map.new(changed_parameters)
        Tenants.update_tenant_ps(tenant, %{server_version: changed_parameters["server_version"]})

        :ok
    end
  end
end
