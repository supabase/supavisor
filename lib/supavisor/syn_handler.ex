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
    Supavisor.join_tenant_pool(id, pid)
  end

  @impl true
  def on_process_unregistered(:tenants, id, _pid, _meta, reason) do
    logger_metadata(id)
    Logger.debug("Process unregistered: #{Supavisor.inspect_id(id)} #{inspect(reason)}")
  end

  @impl true
  def on_process_left(:tenant_pools, {tenant, db_user} = group_name, pid, id, reason) do
    logger_metadata(id)

    if not other_pool_alive?(tenant, db_user, pid, reason) do
      Supavisor.ClientAuthentication.invalidate_local(tenant, db_user)
      Logger.info("SynHandler: invalidated client authentication cache")
    end

    Logger.debug("SynHandler: pool left #{inspect(group_name)}: #{inspect(reason)}")
  end

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

  # `excluding_pid` (the pid this `on_process_left` callback fires for) can still show
  # up in `Supavisor.tenant_pools/2` at this point: when a whole node goes down, :syn
  # purges every pid that was on it by calling this callback for each of them *before*
  # removing any of them from the group table - so while handling one, its doomed
  # siblings (including itself, on a prior/later iteration) can still be listed.
  #
  # Whatever remains after that still isn't necessarily alive: on a multi-node cluster,
  # membership updates propagate asynchronously, so a sibling that died moments ago on
  # another node can still show up as a member here until its removal is received. We
  # check liveness of the remainder rather than trusting group membership alone.
  #
  # We pass the reason only for testing purposes.
  @spec other_pool_alive?(String.t(), String.t(), pid(), atom()) :: boolean()
  defp other_pool_alive?(tenant, db_user, excluding_pid, reason) do
    tenant
    |> Supavisor.tenant_pools(db_user)
    |> Enum.reject(&(&1 == excluding_pid))
    |> Enum.any?(&pool_alive?(&1, reason))
  end

  @spec pool_alive?(pid(), atom()) :: boolean()
  defp pool_alive?(pid, reason) do
    node = (reason == :test_rpc_failure && :nonexistent) || node(pid)

    :erpc.call(
      node,
      Process,
      :alive?,
      [pid],
      5_000
    )
  catch
    kind, reason ->
      Logger.warning(
        "SynHandler: Couldn't check liveness of #{inspect(pid)} on #{node(pid)}, assuming alive: #{inspect({kind, reason})}"
      )

      true
  end

  defp logger_metadata(Supavisor.id(type: type, tenant: tenant, user: user, mode: mode, db: db)),
    do: Logger.metadata(type: type, project: tenant, user: user, mode: mode, db_name: db)
end
