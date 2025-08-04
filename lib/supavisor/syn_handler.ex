defmodule Supavisor.SynHandler do
  @moduledoc """
  Custom defined Syn's callbacks
  """

  @behaviour :syn_event_handler

  require Logger

  @impl true
  def on_process_unregistered(
        :tenants,
        {{type, tenant}, user, mode, db_name, _search_path} = id,
        _pid,
        _meta,
        reason
      ) do
    Logger.debug("Process unregistered: #{inspect(id)} #{inspect(reason)}", %{
      project: tenant,
      user: user,
      mode: mode,
      db_name: db_name,
      type: type
    })
  end

  @impl true
  def resolve_registry_conflict(
        :tenants,
        id,
        {pid1, _, time1} = remote,
        {pid2, _, time2} = local
      ) do
    Logger.info("SynHandler: resolving #{inspect(id)} conflict: #{inspect(local)} vs #{inspect(remote)}")

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
          "SynHandler: Resolving #{inspect(id)} conflict, stop local pid: #{inspect(stop)}, response: #{inspect(resp)}"
        )
      end)
    else
      Logger.warning(
        "SynHandler: Resolving #{inspect(id)} conflict, remote pid: #{inspect(stop)}"
      )
    end

    keep
  end
end
