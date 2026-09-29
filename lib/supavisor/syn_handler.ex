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

    Supavisor.register_tenant_db_user_for_pool(tenant, user, pid)
  end

  @impl true
  def on_process_unregistered(
        :tenants,
        Supavisor.id(type: type, tenant: tenant, user: user, mode: mode, db: db, search_path: _) =
          id,
        _pid,
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

    if not Supavisor.tenant_db_user_registered?(tenant, user) do
      Supavisor.ClientAuthentication.invalidate_local(tenant, user)
      Logger.info("Invalidating client authentication cache")
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
end
