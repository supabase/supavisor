defmodule Supavisor.HotUpgrade do
  @moduledoc false
  require Logger

  @type version_str :: String.t()

  def up(_app, _from_vsn, to_vsn, appup, _transform) do
    appup =
      Enum.reject(appup, fn
        {:load_module, __MODULE__} -> true
        {:load_module, __MODULE__, _} -> true
        _ -> false
      end)

    [
      {:load_module, __MODULE__},
      {:apply, {__MODULE__, :apply_runtime_config, [to_vsn]}}
      | appup
    ] ++ [{:apply, {__MODULE__, :restart_prom_ex, []}}]
  end

  def down(_app, from_vsn, _to_vsn, appup, _transform) do
    [
      {:apply, {Supavisor.HotUpgrade, :apply_runtime_config, [from_vsn]}}
      | appup
    ] ++ [{:apply, {__MODULE__, :restart_prom_ex, []}}]
  end

  @doc """
  Restarts `Supavisor.Monitoring.PromEx` within the top-level supervisor so
  that any new polling metrics introduced by an upgrade (or removed by a
  downgrade) take effect immediately. Must run after all appup instructions
  so that `Application.spec(:supavisor, :vsn)` already reflects the new
  version on the first poll.

  No-ops when PromEx is not present in the supervision tree.

  The :terminate measurement captures the persistent_term.erase GC sweep (sweep 1) since that runs synchronously
   inside Peep's terminate/2 before terminate_child returns. The :restart measurement captures the
  persistent_term.store GC sweep (sweep 2) from Peep's init/1. Both times include whatever else those supervisor
   calls do, but the GC is the dominant cost under load.
  """
  def restart_prom_ex do
    case timed(:terminate, fn ->
           Supervisor.terminate_child(Supavisor.Supervisor, Supavisor.Monitoring.PromEx)
         end) do
      :ok ->
        case timed(:restart, fn ->
               Supervisor.restart_child(Supavisor.Supervisor, Supavisor.Monitoring.PromEx)
             end) do
          {:ok, _} ->
            :ok

          {:error, reason} ->
            Logger.error("PromEx failed to restart after upgrade: #{inspect(reason)}")
            :ok
        end

      {:error, :not_found} ->
        :ok
    end
  end

  defp timed(label, fun) do
    t0 = System.monotonic_time(:millisecond)
    result = fun.()
    elapsed = System.monotonic_time(:millisecond) - t0
    Logger.info("restart_prom_ex #{label} took #{elapsed}ms")
    result
  end

  @spec apply_runtime_config(version_str()) :: any()
  def apply_runtime_config(vsn) do
    path =
      if System.get_env("DEBUG_LOAD_RUNTIME_CONFIG"),
        do: "config/runtime.exs",
        else: "#{System.get_env("RELEASE_ROOT")}/releases/#{vsn}/runtime.exs"

    if File.exists?(path) do
      IO.write("Loading runtime.exs from releases/#{vsn}")

      for {app, config} <-
            Config.Reader.read!(path, env: Application.get_env(:supavisor, :env)) do
        updated_config =
          Config.Reader.merge(
            [{app, Application.get_all_env(app)}],
            [{app, config}]
          )

        Application.put_all_env(updated_config)
      end
    else
      IO.write("No runtime.exs found in releases/#{vsn}")
    end
  end
end
