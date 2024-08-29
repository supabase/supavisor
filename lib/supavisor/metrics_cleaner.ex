defmodule Supavisor.MetricsCleaner do
  @moduledoc false

  use GenServer
  require Logger

  @interval :timer.minutes(30)

  def start_link(args),
    do: GenServer.start_link(__MODULE__, args, name: __MODULE__)

  def init(_args) do
    Logger.info("Starting MetricsCleaner")
    {:ok, %{check_ref: check()}}
  end

  def handle_info(:check, state) do
    Process.cancel_timer(state.check_ref)

    start = System.monotonic_time(:millisecond)
    loop_and_cleanup_metrics_table()
    exec_time = System.monotonic_time(:millisecond) - start

    if exec_time > :timer.seconds(5),
      do: Logger.warning("Metrics check took: #{exec_time} ms")

    {:noreply, %{state | check_ref: check()}}
  end

  def handle_info(msg, state) do
    Logger.error("Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  def check, do: Process.send_after(self(), :check, @interval)

  def loop_and_cleanup_metrics_table do
    metrics_table = Supavisor.Monitoring.PromEx.Metrics
    tenant_registry_table = :syn_registry_by_name_tenants

    fn
      {{_, %{type: type, mode: mode, user: user, tenant: tenant, db_name: db}} = key, _}, _ ->
        case :ets.lookup(tenant_registry_table, {{type, tenant}, user, mode, db}) do
          [] ->
            Logger.warning("Found orphaned metric: #{inspect(key)}")
            :ets.delete(metrics_table, key)

          _ ->
            nil
        end

      _, acc ->
        acc
    end
    |> :ets.foldl(nil, metrics_table)
  end
end
