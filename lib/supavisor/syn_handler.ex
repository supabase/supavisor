defmodule Supavisor.SynHandler do
  @moduledoc """
  Custom defined Syn's callbacks
  """

  @behaviour :syn_event_handler

  require Logger
  require Supavisor

  @impl true
  def on_process_registered(:tenants, id, pid, _, _) do
    logger_metadata(id)
    if node(pid) == node(), do: Supavisor.join_tenant_pool(id, pid)
  end

  @impl true
  def on_process_unregistered(:tenants, id, _pid, _meta, reason) do
    logger_metadata(id)
    Logger.debug("Process unregistered: #{Supavisor.inspect_id(id)} #{inspect(reason)}")
  end

  @impl true
  def on_process_left(:tenant_pools, {tenant, db_user} = group_name, pid, id, reason) do
    logger_metadata(id)

    if last_pool_left?(tenant, db_user, pid, reason) do
      Supavisor.ClientAuthentication.invalidate_local(tenant, db_user)
      Logger.info("SynHandler: invalidated client authentication cache")
    end

    Logger.debug("SynHandler: pool left #{inspect(group_name)}: #{inspect(reason)}")
  end

  def on_process_left(_scope, _group_name, _pid, _id, _reason), do: :ok

  @impl true
  def resolve_registry_conflict(
        :tenants,
        id,
        {pid1, _, time1} = remote,
        {pid2, _, time2} = local
      ) do
    logger_metadata(id)

    Logger.info(
      "SynHandler: resolving #{Supavisor.inspect_id(id)} conflict: #{inspect(local)} vs #{inspect(remote)}"
    )

    {keep, stop} =
      cond do
        time1 < time2 ->
          {pid1, pid2}

        time1 > time2 ->
          {pid2, pid1}

        # If the timestamp is equal, keep the pid with the lower node name
        node(pid1) < node(pid2) ->
          {pid1, pid2}

        true ->
          {pid2, pid1}
      end

    if node() == node(stop) do
      spawn(fn ->
        resp =
          if Process.alive?(stop) do
            try do
              Supervisor.stop(stop, :shutdown, 30_000)
            catch
              error, reason -> {:error, {error, reason}}
            end
          else
            :not_alive
          end

        Logger.warning(
          "SynHandler: Resolving #{Supavisor.inspect_id(id)} conflict, stop local pid: #{inspect(stop)}, response: #{inspect(resp)}"
        )
      end)
    else
      Logger.warning(
        "SynHandler: Resolving #{Supavisor.inspect_id(id)} conflict, remote pid: #{inspect(stop)}"
      )
    end

    keep
  end

  # :syn runs this callback serially in the scope process, after removing the leaving pid
  # from the group - for local deaths and for remote leaves alike - and every node gets a
  # callback for every leaving pool. So the last leave handled on a node sees an empty
  # group; members still listed are pools whose leave this node hasn't handled yet.
  #
  # The exception is a node-down purge: syn calls back for each pid of the down node
  # *before* deleting any of them, so all of that node's members count as gone.
  @spec last_pool_left?(String.t(), String.t(), pid(), term()) :: boolean()
  defp last_pool_left?(tenant, db_user, leaving_pid, reason) do
    tenant
    |> Supavisor.tenant_pools(db_user)
    |> Enum.reject(&(&1 == leaving_pid or on_down_node?(&1, reason)))
    |> Enum.empty?()
  end

  defp on_down_node?(member, {:syn_remote_scope_node_down, _scope, down_node}),
    do: node(member) == down_node

  defp on_down_node?(_member, _reason), do: false

  defp logger_metadata(Supavisor.id(type: type, tenant: tenant, user: user, mode: mode, db: db)),
    do: Logger.metadata(type: type, project: tenant, user: user, mode: mode, db_name: db)
end
