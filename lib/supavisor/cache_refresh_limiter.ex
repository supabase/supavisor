defmodule Supavisor.CacheRefreshLimiter do
  @moduledoc false

  use GenServer

  @table_name Module.concat(__MODULE__, Table)
  @cleanup_interval :timer.minutes(1)
  @cache_refresh_limit 3

  def start_link(_) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @spec cache_refresh_limited?(Supavisor.id()) :: boolean()
  def cache_refresh_limited?(id) do
    counter = :ets.update_counter(@table_name, id, {2, 1}, {id, 0})
    counter > @cache_refresh_limit
  end

  @impl true
  def init([]) do
    :ets.new(@table_name, [:named_table, :public, :set])
    schedule_cleanup()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    :ets.delete_all_objects(@table_name)
    schedule_cleanup()
    {:noreply, state}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
