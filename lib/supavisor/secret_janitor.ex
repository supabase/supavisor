defmodule Supavisor.SecretJanitor do
  @moduledoc """
  Periodically cleans up upstream secrets for terminated pools.
  """

  use GenServer
  require Logger

  @cleanup_interval :timer.hours(1)

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    schedule_cleanup()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_orphaned_secrets()
    schedule_cleanup()
    {:noreply, state}
  end

  @doc """
  Cleans up orphaned upstream secrets for terminated pools.
  Public for testing purposes.
  """
  def cleanup_orphaned_secrets do
    active_pools = get_active_pools()
    cached_secrets = get_cached_upstream_secrets_with_infinite_ttl()

    orphaned = MapSet.difference(cached_secrets, active_pools)

    if MapSet.size(orphaned) > 0 do
      Enum.each(orphaned, fn {tenant, user} ->
        Logger.info("SecretJanitor: Cleaning orphaned secret for #{tenant}/#{user}")
        Supavisor.SecretCache.clean_upstream_secrets(tenant, user)
      end)
    end

    Logger.notice("SecretJanitor: Cleaned #{MapSet.size(orphaned)} orphaned secrets")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp get_active_pools do
    Registry.select(Supavisor.Registry.Tenants, [
      {
        {{:manager, {{:_, :"$1"}, :"$2", :_, :_, :_}}, :_, :_},
        [],
        [{{:"$1", :"$2"}}]
      }
    ])
    |> MapSet.new()
  end

  defp get_cached_upstream_secrets_with_infinite_ttl do
    case Cachex.keys(Supavisor.Cache) do
      {:ok, keys} ->
        keys
        |> Enum.filter(fn
          {:secrets_for_upstream_auth, _tenant, _user} = key ->
            Cachex.ttl(Supavisor.Cache, key) == {:ok, nil}

          _ ->
            false
        end)
        |> MapSet.new(fn {:secrets_for_upstream_auth, tenant, user} -> {tenant, user} end)

      {:error, reason} ->
        Logger.error("SecretJanitor: Failed to get cache keys: #{inspect(reason)}")
        MapSet.new()
    end
  end
end
