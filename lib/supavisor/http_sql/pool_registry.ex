defmodule Supavisor.HttpSql.PoolRegistry do
  @moduledoc """
  Owns the per-`(tenant, user, password_hash)` Postgrex pool map for the
  HTTP /sql endpoint.

  - Pools are started lazily on the first `checkout/2` call.
  - An ETS table `:http_sql_pools` (`set, :public, named_table`) maps
    `key -> {pool_pid, last_used_ms}` for fast lookups.
  - Concurrent races to start the same key are serialized inside the
    GenServer (`:start_pool`) via double-checked locking.
  - A periodic sweep terminates pools idle past `pool_idle_ttl_seconds`.
  - A hard `pool_max_total` cap evicts the LRU pool before accepting a new
    one.

  Test injection: pass `:starter` (a 1-arity fn `pool_opts -> {:ok, pid}`)
  to `start_link/1` to bypass the real `Postgrex.start_link/1` in unit
  tests. Defaults to `&Postgrex.start_link/1`.
  """

  use GenServer
  require Logger

  alias Supavisor.HttpSql.PoolSpec

  @table :http_sql_pools
  @sweep_interval_ms 10_000

  # ----------------------------------------------------------------------- API

  @doc """
  Start the registry. Reads config under `:supavisor -> :http_sql`. Accepts
  `:starter` and `:terminator` opt overrides for testing.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Return a Postgrex pool pid for `ctx`, starting one if missing. Bumps the
  LRU timestamp on hit.

  Required ctx keys: `:tenant_external_id`, `:user`, `:password`, `:database`.

  Returns `{:ok, pid, :hit | :miss}` or `{:error, reason}`.
  """
  @spec checkout(map) :: {:ok, pid, :hit | :miss} | {:error, term}
  def checkout(ctx) when is_map(ctx) do
    key = PoolSpec.key(ctx.tenant_external_id, ctx.user, ctx.password)

    case lookup(key) do
      {:ok, pid} ->
        touch(key)
        {:ok, pid, :hit}

      :error ->
        case GenServer.call(__MODULE__, {:start_pool, key, ctx}, 30_000) do
          {:ok, pid} -> {:ok, pid, :miss}
          {:error, _} = err -> err
        end
    end
  end

  @doc """
  Returns `{total_pools, [{key, pid, last_used_ms}]}`. For diagnostics/tests.
  """
  @spec stats() :: {non_neg_integer, [{tuple, pid, integer}]}
  def stats do
    rows = :ets.tab2list(@table)
    {length(rows), rows}
  end

  @doc """
  Synchronously terminate the pool for `key`. Returns `:ok` even if the key
  wasn't present (idempotent).
  """
  @spec evict(tuple) :: :ok
  def evict(key) do
    GenServer.call(__MODULE__, {:evict, key, :manual})
  end

  # ------------------------------------------------------------------- Server

  @impl true
  def init(opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
    end

    cfg = Application.get_env(:supavisor, :http_sql, [])

    starter =
      Keyword.get(opts, :starter) ||
        Application.get_env(:supavisor, :http_sql_starter) ||
        (&Postgrex.start_link/1)

    terminator =
      Keyword.get(opts, :terminator) ||
        Application.get_env(:supavisor, :http_sql_terminator) ||
        (&default_terminate/1)

    state = %{
      idle_ttl_ms: Keyword.get(cfg, :pool_idle_ttl_seconds, 60) * 1000,
      max_total: Keyword.get(cfg, :pool_max_total, 1000),
      starter: starter,
      terminator: terminator,
      sweep_interval_ms: Keyword.get(opts, :sweep_interval_ms, @sweep_interval_ms)
    }

    schedule_sweep(state.sweep_interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_call({:start_pool, key, ctx}, _from, state) do
    # Double-checked locking: another caller may have just started it.
    case lookup(key) do
      {:ok, pid} ->
        touch(key)
        {:reply, {:ok, pid}, state}

      :error ->
        if :ets.info(@table, :size) >= state.max_total do
          evict_lru(state)
        end

        opts = PoolSpec.build(ctx)
        t0 = System.monotonic_time(:microsecond)

        case state.starter.(opts) do
          {:ok, pid} ->
            Process.monitor(pid)
            now = System.monotonic_time(:millisecond)
            :ets.insert(@table, {key, pid, now})

            :telemetry.execute(
              [:supavisor, :http_sql, :pool, :start, :stop],
              %{duration: System.monotonic_time(:microsecond) - t0},
              %{key: key}
            )

            {:reply, {:ok, pid}, state}

          {:error, reason} = err ->
            :telemetry.execute(
              [:supavisor, :http_sql, :pool, :start, :exception],
              %{duration: System.monotonic_time(:microsecond) - t0},
              %{key: key, reason: inspect(reason)}
            )

            {:reply, err, state}
        end
    end
  end

  def handle_call({:evict, key, reason}, _from, state) do
    do_evict(key, reason, state)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:sweep, state) do
    now = System.monotonic_time(:millisecond)

    for {key, _pid, last} <- :ets.tab2list(@table),
        now - last > state.idle_ttl_ms do
      do_evict(key, :ttl, state)
    end

    schedule_sweep(state.sweep_interval_ms)
    {:noreply, state}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    # Pool died on its own (e.g. backoff_type: :stop after auth failure).
    # Remove its registry entry so the next request retries fresh.
    case :ets.match(@table, {:"$1", pid, :_}) do
      [[key]] ->
        :ets.delete(@table, key)

        :telemetry.execute([:supavisor, :http_sql, :pool, :evict], %{count: 1}, %{
          key: key,
          reason: :down
        })

      _ ->
        :ok
    end

    {:noreply, state}
  end

  # ---------------------------------------------------------------- Internals

  defp lookup(key) do
    case :ets.lookup(@table, key) do
      [{^key, pid, _last}] -> if Process.alive?(pid), do: {:ok, pid}, else: :error
      _ -> :error
    end
  end

  defp touch(key) do
    :ets.update_element(@table, key, {3, System.monotonic_time(:millisecond)})
  end

  defp evict_lru(state) do
    case :ets.tab2list(@table) do
      [] ->
        :ok

      rows ->
        {key, _pid, _last} = Enum.min_by(rows, fn {_k, _p, last} -> last end)
        do_evict(key, :max_total, state)
    end
  end

  defp do_evict(key, reason, state) do
    case :ets.lookup(@table, key) do
      [{^key, pid, _}] ->
        :ets.delete(@table, key)
        state.terminator.(pid)
        :telemetry.execute([:supavisor, :http_sql, :pool, :evict], %{count: 1}, %{
          key: key,
          reason: reason
        })

      _ ->
        :ok
    end
  end

  defp default_terminate(pid) do
    if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5_000), else: :ok
  end

  defp schedule_sweep(interval_ms) do
    Process.send_after(self(), :sweep, interval_ms)
  end
end
