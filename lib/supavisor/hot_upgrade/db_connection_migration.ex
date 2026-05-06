defmodule Supavisor.HotUpgrade.DbConnectionMigration do
  @moduledoc """
  State migration for the `db_connection` 2.9.0 → 2.10.0 hot upgrade.

  v2.10.0 grew the `ts` element of the `DBConnection.ConnectionPool`
  GenServer state from `{monotonic, interval}` to
  `{monotonic, interval, max_lifetime}`. `db_connection` doesn't ship a
  `code_change/3`, so we migrate state ourselves via `:sys.replace_state/2`
  between the `suspend` and `resume` directives in `db_connection.appup`.

  Lives in its own module (rather than `Supavisor.HotUpgrade`) so the
  `db_connection.appup` can `load_module` it first — relups process
  dependency apps before dependents, so by the time `db_connection`'s
  appup executes, the new `Supavisor.HotUpgrade` has not been loaded yet.
  Keeping the migration code in a dedicated module lets us load just
  this one file early without dragging in the rest of `HotUpgrade`.
  """
  require Logger

  def migrate(direction) when direction in [:up, :down] do
    for pid <- find_supervised_pids(DBConnection.ConnectionPool) do
      try do
        :sys.replace_state(pid, fn
          {type, queue, codel, {mono, interval}} when direction == :up ->
            {type, queue, codel, {mono, interval, nil}}

          {type, queue, codel, {mono, interval, _max_lifetime}} when direction == :down ->
            {type, queue, codel, {mono, interval}}

          other ->
            Logger.info("Unexpected state: #{inspect(other)}")
            other
        end)
      catch
        kind, reason ->
          Logger.error(
            "HotUpgrade.DbConnectionMigration: failed to migrate state for #{inspect(pid)}: #{inspect({kind, reason})}"
          )
      end
    end

    :ok
  end

  defp find_supervised_pids(target_mod) do
    roots =
      Enum.flat_map(:application.which_applications(), fn {app, _name, _vsn} ->
        app_root_supervisors(app)
      end)

    walk(roots, target_mod, MapSet.new(roots), []) |> Enum.uniq()
  end

  defp app_root_supervisors(app) do
    case :application_controller.get_master(app) do
      master when is_pid(master) ->
        case :application_master.get_child(master) do
          {root, _app_mod} when is_pid(root) -> [root]
          _ -> []
        end

      _ ->
        []
    end
  end

  defp walk([], _target_mod, _seen, acc), do: acc

  defp walk([sup | rest], target_mod, seen, acc) do
    case safe_which_children(sup) do
      :error ->
        walk(rest, target_mod, seen, acc)

      children ->
        {next, seen, acc} =
          Enum.reduce(children, {rest, seen, acc}, fn
            {_name, pid, :supervisor, mods}, {next, seen, acc} when is_pid(pid) ->
              acc = if target_mod in mods, do: [pid | acc], else: acc

              if MapSet.member?(seen, pid) do
                {next, seen, acc}
              else
                {[pid | next], MapSet.put(seen, pid), acc}
              end

            {_name, pid, :worker, mods}, {next, seen, acc}
            when is_pid(pid) and is_list(mods) ->
              acc = if target_mod in mods, do: [pid | acc], else: acc
              {next, seen, acc}

            {_name, pid, :worker, :dynamic}, {next, seen, acc} when is_pid(pid) ->
              acc = if dynamic_mod_match?(pid, target_mod), do: [pid | acc], else: acc
              {next, seen, acc}

            _, state ->
              state
          end)

        walk(next, target_mod, seen, acc)
    end
  end

  defp safe_which_children(sup) do
    try do
      :supervisor.which_children(sup)
    catch
      _, _ -> :error
    end
  end

  defp dynamic_mod_match?(pid, target_mod) do
    try do
      case :gen.call(pid, self(), :get_modules, 5000) do
        {:ok, mods} when is_list(mods) -> target_mod in mods
        _ -> false
      end
    catch
      _, _ -> false
    end
  end
end
