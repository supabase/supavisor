defmodule Supavisor.SynHandler do
  @moduledoc """
  Custom defined Syn's callbacks
  """
  require Logger
  alias Supavisor.Monitoring.PromEx

  def on_process_unregistered(
        :tenants,
        {tenant, user_alias},
        _pid,
        _meta,
        reason
      ) do
    Logger.debug("Process unregistered: #{inspect({tenant, user_alias})} #{inspect(reason)}")

    # remove all Prometheus metrics for the specified tenant
    PromEx.remove_metrics(tenant, user_alias)
    Supavisor.del_all_cache(tenant, user_alias)
  end

  def resolve_registry_conflict(
        :tenants,
        {tenant, user_alias},
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

        Logger.warn(
          "Resolving #{inspect({tenant, user_alias})} conflict, stop local pid: #{inspect(stop)}, response: #{inspect(resp)}"
        )
      end)
    else
      Logger.warn(
        "Resolving #{inspect({tenant, user_alias})} conflict, remote pid: #{inspect(stop)}"
      )
    end

    keep
  end
end
