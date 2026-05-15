defmodule Supavisor.HttpSql.PoolRegistryTest do
  use ExUnit.Case, async: false

  alias Supavisor.HttpSql.{PoolRegistry, PoolSpec}

  @table :http_sql_pools

  defp fake_pool_proc do
    spawn(fn ->
      receive do
        :stop -> :ok
      end
    end)
  end

  defp install_fake_registry(opts \\ []) do
    starter =
      Keyword.get(opts, :starter, fn _ -> {:ok, fake_pool_proc()} end)

    terminator =
      Keyword.get(opts, :terminator, fn pid ->
        if Process.alive?(pid), do: send(pid, :stop)
        :ok
      end)

    Application.put_env(:supavisor, :http_sql_starter, starter)
    Application.put_env(:supavisor, :http_sql_terminator, terminator)

    # Restart the supervised instance so it picks up the fake starter from
    # Application env in init/1.
    Supervisor.terminate_child(Supavisor.Supervisor, PoolRegistry)
    {:ok, _} = Supervisor.restart_child(Supavisor.Supervisor, PoolRegistry)

    # Wipe ETS state from any prior test.
    if :ets.whereis(@table) != :undefined, do: :ets.delete_all_objects(@table)

    :ok
  end

  setup do
    :ok = install_fake_registry()

    on_exit(fn ->
      Application.delete_env(:supavisor, :http_sql_starter)
      Application.delete_env(:supavisor, :http_sql_terminator)
      Supervisor.terminate_child(Supavisor.Supervisor, PoolRegistry)
      {:ok, _} = Supervisor.restart_child(Supavisor.Supervisor, PoolRegistry)

      if :ets.whereis(@table) != :undefined, do: :ets.delete_all_objects(@table)
    end)

    :ok
  end

  defp ctx(opts \\ []) do
    Enum.into(opts, %{
      tenant_external_id: "tenant_a",
      user: "postgres.tenant_a",
      password: "pwd",
      database: "postgres"
    })
  end

  describe "checkout/1" do
    test "starts a pool on miss" do
      assert {:ok, pid, :miss} = PoolRegistry.checkout(ctx())
      assert Process.alive?(pid)
    end

    test "second checkout for the same key is a hit" do
      assert {:ok, pid, :miss} = PoolRegistry.checkout(ctx())
      assert {:ok, ^pid, :hit} = PoolRegistry.checkout(ctx())
    end

    test "different tenants land in distinct pools" do
      assert {:ok, p1, :miss} = PoolRegistry.checkout(ctx(tenant_external_id: "a"))
      assert {:ok, p2, :miss} = PoolRegistry.checkout(ctx(tenant_external_id: "b"))
      assert p1 != p2
    end

    test "password rotation produces a new pool" do
      assert {:ok, p1, :miss} = PoolRegistry.checkout(ctx(password: "old"))
      assert {:ok, p2, :miss} = PoolRegistry.checkout(ctx(password: "new"))
      assert p1 != p2
    end

    test "starter failure is propagated" do
      install_fake_registry(starter: fn _ -> {:error, :badauth} end)
      assert {:error, :badauth} = PoolRegistry.checkout(ctx())
    end
  end

  describe "evict/1" do
    test "removes the pool and calls terminator" do
      assert {:ok, _pid, :miss} = PoolRegistry.checkout(ctx())
      key = PoolSpec.key("tenant_a", "postgres.tenant_a", "pwd")
      assert :ok = PoolRegistry.evict(key)
      assert {0, []} = PoolRegistry.stats()
    end

    test "evicting a missing key is a no-op" do
      key = PoolSpec.key("nope", "u", "p")
      assert :ok = PoolRegistry.evict(key)
      assert {0, []} = PoolRegistry.stats()
    end
  end

  describe "stats/0" do
    test "reports counts" do
      assert {0, []} = PoolRegistry.stats()
      assert {:ok, _, :miss} = PoolRegistry.checkout(ctx(tenant_external_id: "a"))
      assert {:ok, _, :miss} = PoolRegistry.checkout(ctx(tenant_external_id: "b"))
      assert {2, rows} = PoolRegistry.stats()
      assert length(rows) == 2
    end
  end

  describe "max_total cap" do
    setup do
      original = Application.get_env(:supavisor, :http_sql)

      Application.put_env(
        :supavisor,
        :http_sql,
        Keyword.put(original, :pool_max_total, 2)
      )

      :ok = install_fake_registry()

      on_exit(fn -> Application.put_env(:supavisor, :http_sql, original) end)
      :ok
    end

    test "evicts LRU when at capacity" do
      assert {:ok, p1, :miss} = PoolRegistry.checkout(ctx(tenant_external_id: "a"))
      Process.sleep(5)
      assert {:ok, p2, :miss} = PoolRegistry.checkout(ctx(tenant_external_id: "b"))
      Process.sleep(5)
      # touch b so a is LRU
      assert {:ok, ^p2, :hit} = PoolRegistry.checkout(ctx(tenant_external_id: "b"))
      Process.sleep(5)
      # add c → must evict a
      assert {:ok, _p3, :miss} = PoolRegistry.checkout(ctx(tenant_external_id: "c"))
      assert {2, rows} = PoolRegistry.stats()
      pids = Enum.map(rows, fn {_k, pid, _} -> pid end)
      refute p1 in pids
      assert p2 in pids
    end
  end

  describe "DOWN handling" do
    test "removes registry entry when pool dies" do
      assert {:ok, pid, :miss} = PoolRegistry.checkout(ctx())
      assert {1, _} = PoolRegistry.stats()

      send(pid, :stop)
      Process.sleep(50)

      assert {0, []} = PoolRegistry.stats()
    end
  end
end
