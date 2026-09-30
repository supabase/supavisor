defmodule Supavisor.SynHandler do
  @moduledoc """
  Custom defined Syn's callbacks
  """

  @behaviour :syn_event_handler

  require Logger
  require Supavisor

  @impl true
  def on_process_registered(
        :tenants,
        Supavisor.id(
          type: type,
          tenant: tenant,
          user: user,
          mode: mode,
          db: db
        ),
        pid,
        _,
        _
      ) do
    Logger.metadata(
      project: tenant,
      user: user,
      type: type,
      mode: mode,
      db_name: db
    )

    Supavisor.join_tenant_pool(tenant, user, pid)
  end

  @impl true
  def on_process_unregistered(
        :tenants,
        Supavisor.id(type: type, tenant: tenant, user: user, mode: mode, db: db, search_path: _) =
          id,
        pid,
        _meta,
        reason
      ) do
    Logger.metadata(
      project: tenant,
      user: user,
      type: type,
      mode: mode,
      db_name: db
    )

    if not other_pool_alive?(tenant, user, pid, reason) do
      Supavisor.ClientAuthentication.invalidate_local(tenant, user)
      Logger.info("SynHandler: invalidated client authentication cache")
    end

    Logger.debug("Process unregistered: #{Supavisor.inspect_id(id)} #{inspect(reason)}")
  end

  @impl true
  def resolve_registry_conflict(
        :tenants,
        Supavisor.id(type: type, tenant: tenant, user: user, mode: mode, db: db) =
          id,
        {pid1, _, time1} = remote,
        {pid2, _, time2} = local
      ) do
    meta = %{project: tenant, user: user, mode: mode, db_name: db, type: type}

    Logger.info(
      "SynHandler: resolving #{Supavisor.inspect_id(id)} conflict: #{inspect(local)} vs #{inspect(remote)}",
      meta
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
          "SynHandler: Resolving #{Supavisor.inspect_id(id)} conflict, stop local pid: #{inspect(stop)}, response: #{inspect(resp)}",
          meta
        )
      end)
    else
      Logger.warning(
        "SynHandler: Resolving #{Supavisor.inspect_id(id)} conflict, remote pid: #{inspect(stop)}",
        meta
      )
    end

    keep
  end

  # `excluding_pid` (the pid this unregister callback fires for) is monitored
  # independently by :syn's registry (for its own `id`) and by its pg group (for
  # `{tenant, db_user}`), so the group can still list `excluding_pid` itself as a
  # member for a short while after it dies - the group's own monitor hasn't
  # processed the death yet. On a multi-node cluster, membership updates for pools
  # on other nodes also propagate asynchronously, so a sibling that died moments
  # ago elsewhere can still show up as a member until its removal is received.
  #
  # Excluding `excluding_pid` and checking the liveness of whatever remains rules
  # out both races, instead of trusting group membership alone.
  #
  # we pass the reason only for testing purposes
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
end
