defmodule Supavisor.HotUpgrade do
  @moduledoc false

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
  def up(_app, _from_vsn, to_vsn, appup, _transform),
    do: [{:apply, {Supavisor.HotUpgrade, :apply_runtime_config, [to_vsn]}} | appup]

  @spec down(app(), version_str(), version_str(), [appup()], any()) :: [appup()]
  def down(_app, from_vsn, _to_vsn, appup, _transform),
    do: [{:apply, {Supavisor.HotUpgrade, :apply_runtime_config, [from_vsn]}} | appup]

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
