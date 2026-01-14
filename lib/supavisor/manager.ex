defmodule Supavisor.Manager do
  @moduledoc """
  The Manager is responsible for managing the config and parameter status for a pool
  """

  use GenServer
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
  @spec subscribe(pid, pid) ::
          {:ok, iodata() | [], integer}
          | {:error, :max_clients_reached}
          | {:error, :terminating, term()}
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
  Get the current config for a pool
  """
  @spec get_config(pid | Supavisor.id()) :: map()
  def get_config(manager_or_id) do
    manager = resolve_manager(manager_or_id)
    GenServer.call(manager, :get_config)
  end

  @doc """
  Shuts down the pool with an error.

  Sends error to all clients and stops accepting new connections.
  """
  @spec shutdown_with_error(pid | Supavisor.id(), map()) :: :ok
  def shutdown_with_error(manager_or_id, error) do
    manager = resolve_manager(manager_or_id)
    GenServer.cast(manager, {:shutdown_with_error, error})
  end

  @doc """
  Initiates graceful shutdown of the pool.

  Sends admin shutdown message to all clients and stops accepting new connections.
  Blocks until all clients have disconnected or timeout is reached.

  If timeout is reached, remaining clients are forcefully terminated with an error.
  """
  @spec graceful_shutdown(pid | Supavisor.id(), timeout()) :: :ok
  def graceful_shutdown(manager_or_id, timeout) do
    manager = resolve_manager(manager_or_id)
    GenServer.call(manager, {:graceful_shutdown, timeout}, :infinity)
  end

  ## Callbacks

  @impl true
  def init(args) do
    Helpers.set_log_level(args.log_level)
    tid = :ets.new(__MODULE__, [:protected])

    {{type, tenant}, user, mode, db_name, _search_path} = args.id
    {method, secrets} = args.secrets

    {tenant_record, replica_type} =
      case type do
        :single ->
          tenants = Tenants.get_pool_config_cache(tenant, user)
          {List.first(tenants), :write}

        :cluster ->
          case Tenants.get_cluster_config(tenant, user) do
            {:error, reason} ->
              raise "Failed to get cluster config: #{inspect(reason)}"

            cluster_tenants ->
              selected =
                Enum.find(cluster_tenants, fn ct -> ct.type == :write end) ||
                  List.first(cluster_tenants)

              case selected do
                %Tenants.ClusterTenants{tenant: t, type: rt} -> {t, rt}
                nil -> raise "No cluster tenant configuration found"
              end
          end
      end

    %{
      db_host: db_host,
      db_port: db_port,
      db_database: db_database,
      auth_query: auth_query,
      default_parameter_status: ps,
      ip_version: ip_ver,
      default_pool_size: default_pool_size,
      default_max_clients: default_max_clients,
      client_idle_timeout: client_idle_timeout,
      sni_hostname: sni_hostname,
      feature_flags: feature_flags
    } = tenant_record

    user_config = List.first(tenant_record.users)
    pool_size = (user_config && user_config.pool_size) || default_pool_size
    max_clients = (user_config && user_config.max_clients) || default_max_clients

    auth = %{
      host: String.to_charlist(db_host),
      sni_hostname: if(sni_hostname != nil, do: to_charlist(sni_hostname)),
      port: db_port,
      user: user,
      auth_query: auth_query,
      database: if(db_name != nil, do: db_name, else: db_database),
      application_name: "Supavisor",
      ip_version: Helpers.ip_version(ip_ver, db_host),
      upstream_ssl: tenant_record.upstream_ssl,
      upstream_verify: tenant_record.upstream_verify,
      upstream_tls_ca: Helpers.upstream_cert(tenant_record.upstream_tls_ca),
      require_user: tenant_record.require_user,
      method: method,
      secrets: args.secrets
    }

    secrets_struct = secrets.()

    alias Supavisor.ClientHandler.Auth

    if method == :password or match?(%Auth.SASLSecrets{}, secrets_struct) do
      Supavisor.SecretCache.put_validation_secrets(tenant, user, method, secrets)
      Supavisor.SecretCache.put_upstream_auth_secrets(args.id, method, secrets)
    else
      Supavisor.SecretCache.put_validation_secrets_if_missing(tenant, user, method, secrets)
    end

    persisted_ps = Supavisor.TenantCache.get_parameter_status(args.id)

    state = %{
      id: args.id,
      check_ref: check_subscribers(),
      tid: tid,
      tenant: tenant,
      parameter_status: persisted_ps,
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
      terminating_error: nil,
      drain_caller: nil,
      drain_timer: nil
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

    limit = if state.mode == :session, do: state.pool_size, else: state.max_clients

    {reply, new_state} =
      if :ets.info(state.tid, :size) < limit do
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
    Supavisor.TenantCache.put_parameter_status(state.id, encoded_ps)

    for pid <- state.wait_ps do
      send(pid, {:parameter_status, encoded_ps})
    end

    {:reply, :ok, %{state | parameter_status: encoded_ps, wait_ps: []}}
  end

  def handle_call({:set_parameter_status, _ps}, _, state) do
    {:reply, :ok, state}
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

  def handle_call({:graceful_shutdown, _timeout}, _from, %{terminating_error: error} = state)
      when not is_nil(error) do
    Logger.debug("Pool #{inspect(state.id)} already terminating, skipping graceful shutdown")
    {:reply, :ok, state}
  end

  def handle_call({:graceful_shutdown, timeout}, from, state) do
    Logger.info("Pool #{inspect(state.id)} shutting down gracefully")

    each_client(state, fn {_, pid, _} ->
      Supavisor.ClientHandler.graceful_shutdown(pid)
    end)

    if :ets.info(state.tid, :size) == 0 do
      {:reply, :ok, %{state | terminating_error: Server.admin_shutdown()}}
    else
      drain_timer = Process.send_after(self(), :drain_timeout, timeout)

      {:noreply,
       %{
         state
         | terminating_error: Server.admin_shutdown(),
           drain_caller: from,
           drain_timer: drain_timer
       }}
    end
  end

  @impl true
  def handle_cast({:shutdown_with_error, error}, state) do
    Logger.warning("Shutting down pool #{inspect(state.id)} with error: #{inspect(error)}")
    error_message = Server.encode_error_message(error)

    each_client(state, fn {_, pid, _} ->
      Supavisor.ClientHandler.send_error_and_terminate(pid, error_message)
    end)

    async_stop_sup(state)

    {:noreply, %{state | terminating_error: error}}
  end

  @impl true
  def handle_info({:DOWN, ref, _, _, _}, state) do
    Process.cancel_timer(state.check_ref)
    :ets.take(state.tid, ref)

    state =
      if state.drain_caller && :ets.info(state.tid, :size) == 0 do
        if state.drain_timer, do: Process.cancel_timer(state.drain_timer)
        GenServer.reply(state.drain_caller, :ok)
        %{state | drain_caller: nil, drain_timer: nil}
      else
        state
      end

    {:noreply, %{state | check_ref: check_subscribers()}}
  end

  def handle_info(:drain_timeout, state) do
    Logger.warning("Pool #{inspect(state.id)} drain timeout, force terminating remaining clients")

    error_message = Server.encode_error_message(Server.admin_shutdown())

    each_client(state, fn {_, pid, _} ->
      Supavisor.ClientHandler.send_error_and_terminate(pid, error_message)
    end)

    if state.drain_caller do
      GenServer.reply(state.drain_caller, :ok)
    end

    {:noreply, %{state | drain_caller: nil, drain_timer: nil}}
  end

  def handle_info(:check_subscribers, state) do
    Process.cancel_timer(state.check_ref)

    if :ets.info(state.tid, :size) == 0 do
      Logger.info("No subscribers for pool #{inspect(state.id)}, shutting down")
      async_stop_sup(state)
      {:noreply, state}
    else
      {:noreply, %{state | check_ref: check_subscribers()}}
    end
  end

  def handle_info(msg, state) do
    Logger.warning("Undefined msg: #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, _state) do
    :ok
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

  # Use a task to stop the pool supervisor to avoid deadlock, since the Manager
  # is a child of the TenantSupervisor that Supavisor.stop/1 will terminate
  defp async_stop_sup(state) do
    Task.Supervisor.start_child(Supavisor.PoolTerminator, fn ->
      Supavisor.stop(state.id)
    end)
  end

  defp each_client(state, fun) do
    wrapped = fn client, _acc -> fun.(client) end
    :ets.foldl(wrapped, nil, state.tid)
    :ok
  end

  # Helper to resolve manager PID from either PID or ID
  defp resolve_manager(pid) when is_pid(pid), do: pid

  defp resolve_manager(id) do
    case Supavisor.get_local_manager(id) do
      nil -> raise "Manager not found for pool #{inspect(id)}"
      pid -> pid
    end
  end
end
