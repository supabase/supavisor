defmodule Supavisor.HotUpgrade do
  @moduledoc false
  require Logger

  import Cachex.Spec
  require Record

  Record.defrecord(
    :state,
    [
      :name,
      :strategy,
      :children,
      :dynamics,
      :intensity,
      :period,
      :restarts,
      :dynamic_restarts,
      :auto_shutdown,
      :module,
      :args
    ]
  )

  Record.defrecord(
    :child,
    [:pid, :id, :mfargs, :restart_type, :significant, :shutdown, :child_type, :modules]
  )

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

  def reint_funs() do
    reinit_pool_args()
    reinit_auth_query()
  end

  def reinit_pool_args() do
    for [_tenant, pid, _meta] <-
          Registry.select(Supavisor.Registry.TenantSups, [
            {{:"$1", :"$2", :"$3"}, [], [[:"$1", :"$2", :"$3"]]}
          ]),
        {_, child_pid, _, [:poolboy]} <- Supervisor.which_children(pid),
        linked_pid <- Process.info(child_pid)[:links],
        match?(
          {:supervisor, :poolboy_sup, _},
          Process.info(linked_pid)[:dictionary][:"$initial_call"]
        ),
        {status, state} = get_state(linked_pid),
        match?(:ok, status),
        Record.is_record(state, :state),
        state(state, :module) == :poolboy_sup do
      :sys.replace_state(linked_pid, fn state ->
        db_handler = Supavisor.DbHandler
        {^db_handler, args} = state(state, :args)

        args =
          Map.update!(args, :auth, fn auth ->
            Map.put(auth, :password, enc(auth.password.()))
            |> Map.put(:secrets, enc(auth.secrets.()))
          end)

        {[^db_handler], %{^db_handler => child}} = state(state, :children)

        children =
          {[db_handler], %{db_handler => child(child, mfargs: {db_handler, :start_link, [args]})}}

        state(state, args: {db_handler, args}, children: children)
      end)
    end
  end

  def reinit_auth_query() do
    Supavisor.Cache
    |> Cachex.stream!()
    |> Enum.each(fn entry(key: key, value: value) ->
      case value do
        {:cached, {:ok, {:auth_query, auth}}} when is_function(auth) ->
          Logger.debug("Reinitializing secret auth_query: #{inspect(key)}")
          new = {:cached, {:ok, {:auth_query, enc(auth.())}}}
          Cachex.put(Supavisor.Cache, key, new)

        {:cached, {:ok, {:auth_query_md5, auth}}} when is_function(auth) ->
          Logger.debug("Reinitializing secret auth_query_md5: #{inspect(key)}")
          new = {:cached, {:ok, {:auth_query_md5, enc(auth.())}}}
          Cachex.put(Supavisor.Cache, key, new)

        other ->
          Logger.debug("Skipping:#{inspect(key)} #{inspect(other)}")
      end
    end)
  end

  @spec enc(term) :: fun
  def enc(val), do: apply(__MODULE__, :do_enc, [val])

  @spec do_enc(term) :: fun
  def do_enc(val), do: fn -> val end

  def get_state(pid) do
    try do
      {:ok, :sys.get_state(pid)}
    catch
      type, exception ->
        IO.write("Error getting state: #{inspect(exception)}")
        {:error, {type, exception}}
    end
  end
end
