defmodule Supavisor.HotUpgrade do
  @moduledoc false
  require Logger

  import Cachex.Spec

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
    [
      {:apply, {__MODULE__, :apply_runtime_config, [to_vsn]}},
      {:apply, {__MODULE__, :reint_funs, []}}
    ] ++ appup
  end

  @spec down(app(), version_str(), version_str(), [appup()], any()) :: [appup()]
  def down(_app, from_vsn, _to_vsn, appup, _transform) do
    [
      {:apply, {Supavisor.HotUpgrade, :apply_runtime_config, [from_vsn]}},
      {:apply, {__MODULE__, :reint_funs, []}}
    ] ++ appup
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

  def reint_funs do
    reinit_auth_query()
  end

  def reinit_auth_query do
    reinit_validation_secrets()
    reinit_upstream_secrets()
  end

  defp reinit_validation_secrets do
    Supavisor.Cache
    |> Cachex.stream!()
    |> Enum.each(fn entry(key: key, value: value) ->
      case {key, value} do
        {{:secrets_for_validation, tenant, user}, {:cached, {method, secrets_fn}}}
        when is_function(secrets_fn) ->
          Logger.debug("Reinitializing validation secrets: #{tenant}/#{user}")
          new = {:cached, {method, enc(secrets_fn.())}}
          Cachex.put(Supavisor.Cache, key, new)

        {{:secrets_check, tenant, user}, {:cached, {method, secrets_fn}}}
        when is_function(secrets_fn) ->
          Logger.debug("Reinitializing secrets_check: #{tenant}/#{user}")
          new = {:cached, {method, enc(secrets_fn.())}}
          Cachex.put(Supavisor.Cache, key, new)

        _other ->
          :ok
      end
    end)
  end

  defp reinit_upstream_secrets do
    for [_id, _pid, table] <-
          Registry.select(Supavisor.Registry.Tenants, [
            {{{:cache, :"$1"}, :"$2", :"$3"}, [], [[:"$1", :"$2", :"$3"]]}
          ]) do
      case :ets.lookup(table, :upstream_auth_secrets) do
        [{:upstream_auth_secrets, {method, secrets_fn}}] when is_function(secrets_fn) ->
          Logger.debug("Reinitializing upstream_auth_secrets in tenant cache")
          :ets.insert(table, {:upstream_auth_secrets, {method, enc(secrets_fn.())}})

        _ ->
          :ok
      end
    end
  end

  @spec enc(term) :: fun
  def enc(val), do: apply(__MODULE__, :do_enc, [val])

  @spec do_enc(term) :: fun
  def do_enc(val), do: fn -> val end
end
