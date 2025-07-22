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
        {pid1, _, time1},
        {pid2, _, time2}
      ) do
    {keep, stop} =
      if time1 < time2 do
        {pid1, pid2}
      else
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
