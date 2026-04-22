defmodule Supavisor.HotUpgrade do
  @moduledoc false
  require Logger

  @type app :: atom
  @type version_str :: String.t()
  @type path_str :: String.t()
  @type change :: :soft | {:advanced, [term]}
  @type dep_mods :: [module]
  @type appup_ver :: charlist | binary
  @type instruction ::
          {:add_module, module}
          | {:delete_module, module}
          | {:update, module, :supervisor | change}
          | {:update, module, change, dep_mods}
          | {:load_module, module}
          | {:load_module, module, dep_mods}
          | {:apply, {module, atom, [term]}}
          | {:add_application, atom}
          | {:remove_application, atom}
          | {:restart_application, atom}
          | :restart_new_emulator
          | :restart_emulator
  @type upgrade_instructions :: [{appup_ver, instruction}]
  @type downgrade_instructions :: [{appup_ver, instruction}]
  @type appup :: {appup_ver, upgrade_instructions, downgrade_instructions}

  @spec up(app(), version_str(), version_str(), [appup()], any()) :: [appup()]
  def up(_app, _from_vsn, to_vsn, appup, _transform) do
    explicit = [__MODULE__, Supavisor.ConnectLimiter, Supavisor.TenantSupervisor]

    appup =
      Enum.reject(appup, fn
        {:load_module, mod} -> mod in explicit
        {:load_module, mod, _} -> mod in explicit
        {:add_module, mod} -> mod in explicit
        {:delete_module, mod} -> mod in explicit
        {:update, mod, _} -> mod in explicit
        {:update, mod, _, _} -> mod in explicit
        _ -> false
      end)

    [
      {:load_module, __MODULE__},
      {:apply, {__MODULE__, :apply_runtime_config, [to_vsn]}},
      {:apply, {__MODULE__, :remove_access_log_handler, []}}
    ] ++
      appup ++
      [
        {:add_module, Supavisor.ConnectLimiter},
        {:update, Supavisor.TenantSupervisor, :supervisor},
        {:apply, {__MODULE__, :start_connect_limiters, []}}
      ]
  end

  @spec down(app(), version_str(), version_str(), [appup()], any()) :: [appup()]
  def down(_app, from_vsn, _to_vsn, appup, _transform) do
    explicit = [__MODULE__, Supavisor.ConnectLimiter, Supavisor.TenantSupervisor]

    appup =
      Enum.reject(appup, fn
        {:load_module, mod} -> mod in explicit
        {:load_module, mod, _} -> mod in explicit
        {:add_module, mod} -> mod in explicit
        {:delete_module, mod} -> mod in explicit
        {:update, mod, _} -> mod in explicit
        {:update, mod, _, _} -> mod in explicit
        _ -> false
      end)

    [
      {:apply, {Supavisor.HotUpgrade, :apply_runtime_config, [from_vsn]}},
      {:apply, {__MODULE__, :stop_connect_limiters, []}}
    ] ++
      appup ++
      [
        {:update, Supavisor.TenantSupervisor, :supervisor},
        {:delete_module, Supavisor.ConnectLimiter}
      ]
  end

  def remove_access_log_handler do
    :logger.remove_handler(:access_log)
  end

  def start_connect_limiters do
    for {pid, id} <- tenant_supervisors() do
      try do
        Supervisor.start_child(pid, {Supavisor.ConnectLimiter, [id: id]})
      catch
        :exit, _ -> :ok
      end
    end
  end

  def stop_connect_limiters do
    for {pid, _id} <- tenant_supervisors() do
      try do
        Supervisor.terminate_child(pid, Supavisor.ConnectLimiter)
        Supervisor.delete_child(pid, Supavisor.ConnectLimiter)
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp tenant_supervisors do
    Registry.select(Supavisor.Registry.TenantSups, [{{:_, :"$1", :"$2"}, [], [{{:"$1", :"$2"}}]}])
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
