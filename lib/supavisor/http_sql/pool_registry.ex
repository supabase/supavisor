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

  @doc """
  Evict every pool whose key's tenant_external_id matches. Used when a
  tenant is updated/banned/has credentials rotated so that in-flight
  HTTP-SQL pools don't continue serving with stale state.
  """
  @spec evict_tenant(String.t()) :: :ok
  def evict_tenant(tenant_external_id) when is_binary(tenant_external_id) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      _pid -> GenServer.cast(__MODULE__, {:evict_tenant, tenant_external_id})
    end
  end

  # ------------------------------------------------------------------- Server

  @impl true
  def init(opts) do
    # Trap exits: pool supervisors are linked to this process. Without
    # trapping, any pool-tree termination would crash the registry and
    # erase the entire ETS index of live pools.
    Process.flag(:trap_exit, true)

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
      sweep_interval_ms: Keyword.get(opts, :sweep_interval_ms, @sweep_interval_ms),
      # Reverse index pid → key. Maintained on insert/delete so the DOWN
      # handler can look up the dead pool's key in O(1).
      pid_to_key: %{}
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
        state =
          if :ets.info(@table, :size) >= state.max_total,
            do: evict_lru(state),
            else: state

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
              tenant_user_tags(key)
            )

            {:reply, {:ok, pid}, %{state | pid_to_key: Map.put(state.pid_to_key, pid, key)}}

          {:error, reason} = err ->
            :telemetry.execute(
              [:supavisor, :http_sql, :pool, :start, :exception],
              %{duration: System.monotonic_time(:microsecond) - t0},
              Map.put(tenant_user_tags(key), :reason, inspect(reason))
            )

            {:reply, err, state}
        end
    end
  end

  def handle_call({:evict, key, reason}, _from, state) do
    new_state = do_evict(key, reason, state)
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_cast({:evict_tenant, tenant_external_id}, state) do
    # Iterate ETS, match-spec on the first tuple element of the key
    # (which is `tenant_external_id`).
    new_state =
      :ets.tab2list(@table)
      |> Enum.reduce(state, fn
        {{^tenant_external_id, _user, _pwd_hash} = key, _pid, _last}, acc ->
          do_evict(key, :tenant_invalidated, acc)

        _, acc ->
          acc
      end)

    {:noreply, new_state}
  end

  @impl true
  def handle_info(:sweep, state) do
    now = System.monotonic_time(:millisecond)

    new_state =
      :ets.tab2list(@table)
      |> Enum.reduce(state, fn
        {key, _pid, last}, acc when now - last > state.idle_ttl_ms ->
          do_evict(key, :ttl, acc)

        _, acc ->
          acc
      end)

    schedule_sweep(state.sweep_interval_ms)
    {:noreply, new_state}
  end

  # Linked pool died. We still get a `:DOWN` from `Process.monitor/1` so
  # the bookkeeping happens there; here we just log and stay alive.
  def handle_info({:EXIT, _pid, reason}, state) do
    unless reason in [:normal, :shutdown] do
      Logger.debug("HttpSql.PoolRegistry: linked process exited: #{inspect(reason)}")
    end

    {:noreply, state}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    # O(1) reverse lookup pid → key. Without this, the previous
    # `:ets.match` on pid was O(table_size) per pool death — a hotspot
    # when upstream Postgres restarts cause many pools to flap at once.
    case Map.fetch(state.pid_to_key, pid) do
      {:ok, key} ->
        :ets.delete(@table, key)

        :telemetry.execute(
          [:supavisor, :http_sql, :pool, :evict],
          %{count: 1},
          Map.put(tenant_user_tags(key), :reason, :down)
        )

        {:noreply, %{state | pid_to_key: Map.delete(state.pid_to_key, pid)}}

      :error ->
        {:noreply, state}
    end
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
        state

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

        :telemetry.execute(
          [:supavisor, :http_sql, :pool, :evict],
          %{count: 1},
          Map.put(tenant_user_tags(key), :reason, reason)
        )

        %{state | pid_to_key: Map.delete(state.pid_to_key, pid)}

      _ ->
        state
    end
  end

  # Async terminate via the existing Task.Supervisor so the registry
  # GenServer isn't blocked for up to 5s by a slow GenServer.stop.
  # Tests inject a synchronous terminator via opts/Application env.
  defp default_terminate(pid) do
    Task.Supervisor.start_child(Supavisor.PoolTerminator, fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5_000)
    end)

    :ok
  end

  defp schedule_sweep(interval_ms) do
    Process.send_after(self(), :sweep, interval_ms)
  end

  # Telemetry metadata MUST NOT carry the password hash (third tuple
  # element of the key). Even though SHA-256 is one-way, leaking a
  # stable per-password fingerprint to every metrics handler creates a
  # cross-request correlation vector and a pre-computation oracle.
  defp tenant_user_tags({tenant, user, _pwd_hash}),
    do: %{tenant: tenant, user: user}
end
