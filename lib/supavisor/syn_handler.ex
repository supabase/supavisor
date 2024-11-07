defmodule Supavisor.SynHandler do
  @moduledoc """
  Custom defined Syn's callbacks
  """

  @behaviour :syn_event_handler

  require Logger

  alias Supavisor.Monitoring.PromEx

  @impl true
  def on_process_unregistered(
        :tenants,
        {{_type, _tenant}, _user, _mode, _db_name, _search_path} = id,
        _pid,
        meta,
        reason
      ) do
    Logger.debug("Process unregistered: #{inspect(id)} #{inspect(reason)}")

    case meta do
      %{port: port, listener: listener} ->
        try do
          :ranch.stop_listener(id)

          Logger.notice(
            "Stopped listener #{inspect(id)} on port #{inspect(port)} listener #{inspect(listener)}"
          )
        rescue
          exception ->
            Logger.error("Failed to stop listener #{inspect(id)} #{Exception.message(exception)}")
        end

      _ ->
        nil
    end

    # remove all Prometheus metrics for the specified tenant
    PromEx.remove_metrics(id)
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
          "Resolving #{inspect(id)} conflict, stop local pid: #{inspect(stop)}, response: #{inspect(resp)}"
        )
      end)
    else
      Logger.warning("Resolving #{inspect(id)} conflict, remote pid: #{inspect(stop)}")
    end

    keep
  end
end
