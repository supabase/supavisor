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

  # Assumes peep storage is `:striped`
  defp loop_and_cleanup_metrics_table do
    %Peep.Persistent{storage: {_, tids}} =
      Peep.Persistent.fetch(Supavisor.Monitoring.PromEx.Metrics)

    tids
    |> Tuple.to_list()
    |> Enum.sum_by(&clean_table/1)
  end

  defp clean_table(tid) do
    func =
      fn {key, _val}, acc ->
        # We use elem/2 instead of pattern matching because the key may be a tuple with size 2 or 3
        with %{
               type: type,
               mode: mode,
               user: user,
               tenant: tenant,
               db_name: db,
               search_path: search_path
             } <- elem(key, 1),
             [] <-
               :ets.lookup(@tenant_registry_table, {{type, tenant}, user, mode, db, search_path}) do
          :ets.delete(tid, key)
          acc + 1
        else
          _ -> acc
        end
      end

    :ets.foldl(func, 0, tid)
  end
end
