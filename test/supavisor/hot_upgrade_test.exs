defmodule Supavisor.HotUpgradeTest do
  use Supavisor.DataCase, async: false

  alias Supavisor.HotUpgrade
  alias Postgrex, as: P

  @tenant "is_manager"

  setup do
    Cachex.clear(Supavisor.Cache)
    :ok
  end

  defp setup_pool(mode) do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    port =
      case mode do
        :transaction -> Application.get_env(:supavisor, :proxy_port_transaction)
        :session -> Application.get_env(:supavisor, :proxy_port_session)
      end

    {:ok, proxy} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: port,
        database: db_conf[:database],
        password: db_conf[:password],
        username: db_conf[:username] <> "." <> @tenant
      )

    %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])

    %{proxy: proxy, db_conf: db_conf, user: db_conf[:username], mode: mode, port: port}
  end

  for mode <- [:transaction, :session] do
    test "reinit_validation_secrets replaces cached function in #{mode} mode" do
      %{user: user, proxy: proxy, db_conf: db_conf, port: port} = setup_pool(unquote(mode))

      key = {:secrets_for_validation, @tenant, user}
      {:ok, {:cached, {method, original_fn}}} = Cachex.get(Supavisor.Cache, key)

      HotUpgrade.reinit_auth_query()

      {:ok, {:cached, {^method, new_fn}}} = Cachex.get(Supavisor.Cache, key)
      assert is_function(new_fn, 0)
      refute new_fn == original_fn

      %P.Result{rows: [[2]]} = P.query!(proxy, "SELECT 2", [])

      {:ok, new_proxy} =
        Postgrex.start_link(
          hostname: db_conf[:hostname],
          port: port,
          database: db_conf[:database],
          password: db_conf[:password],
          username: db_conf[:username] <> "." <> @tenant
        )

      %P.Result{rows: [[3]]} = P.query!(new_proxy, "SELECT 3", [])

      GenServer.stop(new_proxy)
    end

    test "reinit_upstream_secrets replaces cached function in #{mode} mode" do
      %{user: user, db_conf: db_conf, proxy: proxy, port: port} = setup_pool(unquote(mode))

      id = {{:single, @tenant}, user, unquote(mode), db_conf[:database], nil}
      table = get_tenant_table(id)

      [{:upstream_auth_secrets, {method, original_fn}}] =
        :ets.lookup(table, :upstream_auth_secrets)

      HotUpgrade.reinit_auth_query()

      [{:upstream_auth_secrets, {^method, new_fn}}] = :ets.lookup(table, :upstream_auth_secrets)
      assert is_function(new_fn, 0)
      refute new_fn == original_fn

      %P.Result{rows: [[2]]} = P.query!(proxy, "SELECT 2", [])

      {:ok, new_proxy} =
        Postgrex.start_link(
          hostname: db_conf[:hostname],
          port: port,
          database: db_conf[:database],
          password: db_conf[:password],
          username: db_conf[:username] <> "." <> @tenant
        )

      %P.Result{rows: [[3]]} = P.query!(new_proxy, "SELECT 3", [])

      GenServer.stop(new_proxy)
    end
  end

  defp get_tenant_table(id) do
    [{_pid, table}] = Registry.lookup(Supavisor.Registry.Tenants, {:cache, id})
    table
  end
end
