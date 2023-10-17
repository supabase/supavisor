defmodule Supavisor do
  @moduledoc false
  require Logger
  alias Supavisor.Helpers, as: H
  alias Supavisor.{Tenants, Tenants.Tenant, Manager}

  @type sock :: tcp_sock() | ssl_sock()
  @type ssl_sock :: {:ssl, :ssl.sslsocket()}
  @type tcp_sock :: {:gen_tcp, :gen_tcp.socket()}
  @type workers :: %{manager: pid, pool: pid}
  @type secrets :: {:password | :auth_query, fun()}
  @type mode :: :transaction | :session | :native
  @type id :: {String.t(), String.t(), mode}
  @type subscribe_opts :: %{workers: workers, ps: list, idle_timeout: integer}

  @registry Supavisor.Registry.Tenants

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

  @spec del_all_cache(String.t(), String.t()) :: map()
  def del_all_cache(tenant, user) do
    %{
      secrets: Cachex.del(Supavisor.Cache, {:secrets, tenant, user}),
      metrics: Cachex.del(Supavisor.Cache, {:metrics, tenant})
    }
  end

  @spec get_local_pool(id) :: pid | nil
  def get_local_pool(id) do
    case Registry.lookup(@registry, {:pool, id}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  @spec get_local_manager(id) :: pid | nil
  def get_local_manager(id) do
    case Registry.lookup(@registry, {:manager, id}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  @spec id(String.t(), String.t(), mode, mode) :: id
  def id(tenant, user, port_mode, user_mode) do
    # temporary hack
    mode =
      if port_mode == :transaction do
        user_mode
      else
        port_mode
      end

    {tenant, user, mode}
  end

  ## Internal functions

  @spec start_local_pool(id, secrets) :: {:ok, pid} | {:error, any}
  defp start_local_pool({tenant, user, mode} = id, {method, secrets}) do
    Logger.debug("Starting pool for #{inspect(id)}")

    case Tenants.get_pool_config(tenant, secrets.().alias) do
      %Tenant{} = tenant_record ->
        %{
          db_host: db_host,
          db_port: db_port,
          db_database: db_database,
          default_parameter_status: ps,
          ip_version: ip_ver,
          default_pool_size: def_pool_size,
          default_max_clients: def_max_clients,
          client_idle_timeout: client_idle_timeout,
          default_pool_strategy: default_pool_strategy,
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
          database: db_database,
          password: fn -> db_pass end,
          application_name: "supavisor",
          ip_version: H.ip_version(ip_ver, db_host),
          upstream_ssl: tenant_record.upstream_ssl,
          upstream_verify: tenant_record.upstream_verify,
          upstream_tls_ca: H.upstream_cert(tenant_record.upstream_tls_ca),
          require_user: tenant_record.require_user,
          method: method,
          secrets: secrets
        }

        args = %{
          id: id,
          tenant: tenant,
          user: user,
          auth: auth,
          pool_size: pool_size,
          mode: mode,
          default_parameter_status: ps,
          max_clients: max_clients,
          client_idle_timeout: client_idle_timeout,
          default_pool_strategy: default_pool_strategy
        }

        DynamicSupervisor.start_child(
          {:via, PartitionSupervisor, {Supavisor.DynamicSupervisor, id}},
          {Supavisor.TenantSupervisor, args}
        )
        |> case do
          {:error, {:already_started, pid}} -> {:ok, pid}
          resp -> resp
        end

      _ ->
        Logger.error("Can't find tenant with external_id #{inspect(id)}")

        {:error, :tenant_not_found}
    end
  end

  @spec set_parameter_status(id, [{binary, binary}]) :: :ok | {:error, :not_found}
  def set_parameter_status(id, ps) do
    case get_local_manager(id) do
      nil -> {:error, :not_found}
      pid -> Manager.set_parameter_status(pid, ps)
    end
  end
end
