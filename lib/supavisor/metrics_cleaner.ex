defmodule Supavisor.MetricsCleaner do
  @moduledoc false

  use GenServer
  require Logger

  @interval :timer.minutes(30)
  @name __MODULE__
  @tenant_registry_table :syn_registry_by_name_tenants

  def start_link(args),
    do: GenServer.start_link(__MODULE__, args, name: @name)

  def clean do
    GenServer.cast(@name, :clean)
  end

  def init(_args) do
    Logger.info("Starting MetricsCleaner")

    :telemetry.attach(
      {__MODULE__, :report},
      [:supavisor, :metrics_cleaner, :stop],
      &__MODULE__.__report_long_cleanups__/4,
      []
    )

    {:ok, %{check_ref: check()}}
  end

  @doc false
  def __report_long_cleanups__(_event_name, %{duration: duration}, _metadata, _config) do
    exec_time = :erlang.convert_time_unit(duration, :native, :millisecond)

    if exec_time > :timer.seconds(5),
      do: Logger.warning("Metrics check took: #{exec_time} ms")
  end

  def handle_continue(:clean, state) do
    Process.cancel_timer(state.check_ref)

    :telemetry.span([:supavisor, :metrics_cleaner], %{}, fn ->
      count = loop_and_cleanup_metrics_table()
      Logger.info("Cleaned #{count} orphaned metrics")
      {[], %{orphaned_metrics: count}, %{}}
    end)

    {:noreply, %{state | check_ref: check()}}
  end

  def handle_cast(:clean, state) do
    {:noreply, state, {:continue, :clean}}
  end

  def handle_info(:check, state) do
    {:noreply, state, {:continue, :clean}}
  end

  def handle_info(msg, state) do
    Logger.error("Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  defp check, do: Process.send_after(self(), :check, @interval)

  defp loop_and_cleanup_metrics_table do
    {_, {tags_tid, metric_tids, reverse_tags_tid, cache_tid}} =
      Peep.Persistent.storage(Supavisor.Monitoring.PromEx.Metrics)

    metric_tids
    |> Tuple.to_list()
    |> Enum.sum_by(&clean_table(&1, tags_tid, reverse_tags_tid, cache_tid))
  end

  defp clean_table(tid, tags_tid, reverse_tags_tid, cache_tid) do
    :ets.foldl(
      fn {{metric_id, tags_id}, _val}, acc ->
        tags = resolve_tags(reverse_tags_tid, tags_id)

        if tags[:tenant] && tenant_down?(tags) do
          :ets.delete(tid, {metric_id, tags_id})
          # Clean up tag mappings and label cache for this tags_id.
          # Other scheduler tables may still reference this tags_id,
          # but orphaned entries in tags/reverse_tags are harmless
          # and will be cleaned on subsequent passes once all references
          # are gone.
          :ets.delete(cache_tid, tags_id)
          :ets.delete(reverse_tags_tid, tags_id)
          :ets.delete(tags_tid, tags)
          acc + 1
        else
          acc
        end
      end,
      0,
      tid
    )
  end

  defp resolve_tags(reverse_tags_tid, tags_id) do
    case :ets.lookup(reverse_tags_tid, tags_id) do
      [{_, tags}] -> tags
      [] -> %{}
    end
  end

  defp tenant_down?(%{
         type: type,
         mode: mode,
         user: user,
         tenant: tenant,
         db_name: db,
         search_path: search_path
       }) do
    :ets.lookup(@tenant_registry_table, {{type, tenant}, user, mode, db, search_path}) == []
  end

  defp tenant_down?(%{tenant: tenant}) do
    Registry.lookup(Supavisor.Registry.TenantSups, tenant) == []
  end

  defp tenant_down?(_), do: false
end
