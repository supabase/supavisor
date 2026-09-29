defmodule Supavisor.Integration.ClusterRoutingTest do
  use Supavisor.DataCase, async: false

  @moduletag integration: true

  require Supavisor

  alias Supavisor.Tenants

  @psql System.find_executable("psql")
  if is_nil(@psql) do
    @moduletag skip: "psql executable is required for cluster routing integration checks"
  end

  @write_tenant "routing_write_tenant"
  @read_tenant "routing_read_tenant"
  @cluster_alias "routing_cluster"

  @write_only_tenant "routing_write_only_tenant"
  @write_only_cluster "routing_write_only_cluster"

  setup do
    repo_conf = Application.fetch_env!(:supavisor, Repo)

    %{
      repo_conf: repo_conf,
      psql: @psql,
      port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
      db: repo_conf[:database]
    }
  end

  describe "transaction-mode cluster routing (simple query)" do
    setup %{repo_conf: repo_conf} do
      # NOTE: The cluster's write member and read member are distinct tenants but the same backend.
      create_member_tenant(@write_tenant, repo_conf)
      create_member_tenant(@read_tenant, repo_conf)

      {:ok, _} =
        Tenants.create_cluster(%{
          active: true,
          alias: @cluster_alias,
          cluster_tenants: [
            %{
              type: "write",
              cluster_alias: @cluster_alias,
              tenant_external_id: @write_tenant,
              active: true
            },
            %{
              type: "read",
              cluster_alias: @cluster_alias,
              tenant_external_id: @read_tenant,
              active: true
            }
          ]
        })

      on_exit(fn ->
        stop_cluster(@cluster_alias, repo_conf)
        Tenants.delete_cluster_by_alias(@cluster_alias)
        Tenants.delete_tenant_by_external_id(@write_tenant)
        Tenants.delete_tenant_by_external_id(@read_tenant)
      end)

      %{user: "#{repo_conf[:username]}.cluster.#{@cluster_alias}"}
    end

    test "read-safe query routes to the read pool", ctx do
      ref = attach_pool_checkout_handler()

      run_psql!(ctx, "SELECT 1")

      assert_receive {^ref, %{duration: _}, %{replica_type: :read}}, 5_000
    end

    test "write query routes to the write pool", ctx do
      ref = attach_pool_checkout_handler()

      run_psql!(ctx, "CREATE TEMP TABLE routing_probe (id integer)")

      assert_receive {^ref, %{duration: _}, %{replica_type: :write}}, 5_000
    end
  end

  describe "fallback when no read member exists" do
    setup %{repo_conf: repo_conf} do
      create_member_tenant(@write_only_tenant, repo_conf)

      {:ok, _} =
        Tenants.create_cluster(%{
          active: true,
          alias: @write_only_cluster,
          cluster_tenants: [
            %{
              type: "write",
              cluster_alias: @write_only_cluster,
              tenant_external_id: @write_only_tenant,
              active: true
            }
          ]
        })

      on_exit(fn ->
        stop_cluster(@write_only_cluster, repo_conf)
        Tenants.delete_cluster_by_alias(@write_only_cluster)
        Tenants.delete_tenant_by_external_id(@write_only_tenant)
      end)

      %{user: "#{repo_conf[:username]}.cluster.#{@write_only_cluster}"}
    end

    test "read-safe query falls back to the write pool", ctx do
      ref = attach_pool_checkout_handler()

      run_psql!(ctx, "SELECT 1")

      assert_receive {^ref, %{duration: _}, %{replica_type: :write}}, 5_000
    end
  end

  defp create_member_tenant(external_id, repo_conf) do
    {:ok, _} =
      Tenants.create_tenant(%{
        default_parameter_status: %{},
        db_host: repo_conf[:hostname],
        db_port: repo_conf[:port],
        db_database: repo_conf[:database],
        external_id: external_id,
        require_user: true,
        users: [
          %{
            "db_user" => repo_conf[:username],
            "db_password" => repo_conf[:password],
            "pool_size" => 5,
            "mode_type" => "transaction"
          }
        ]
      })
  end

  defp run_psql!(ctx, sql, opts \\ []) do
    {output, status} = run_psql(ctx, sql, opts)
    assert status == 0, output

    output
    |> String.trim()
    |> String.split("\n")
    |> List.last()
    |> String.trim()
  end

  defp run_psql(ctx, sql, opts) do
    db_conf = Application.fetch_env!(:supavisor, Repo)

    env =
      [
        {"PGHOST", "127.0.0.1"},
        {"PGPORT", Integer.to_string(ctx.port)},
        {"PGDATABASE", ctx.db},
        {"PGUSER", ctx.user},
        {"PGPASSWORD", db_conf[:password]},
        {"PGSSLMODE", "disable"}
      ]
      |> maybe_put_pgoptions(opts[:pgoptions])

    args = [
      "--no-psqlrc",
      "--set",
      "ON_ERROR_STOP=on",
      "--tuples-only",
      "-A",
      "-c",
      sql
    ]

    System.cmd(ctx.psql, args, env: env, stderr_to_stdout: true)
  end

  defp maybe_put_pgoptions(env, nil), do: env
  defp maybe_put_pgoptions(env, ""), do: env
  defp maybe_put_pgoptions(env, value), do: [{"PGOPTIONS", value} | env]

  defp attach_pool_checkout_handler do
    ref = make_ref()

    :ok =
      :telemetry.attach(
        {__MODULE__, ref},
        [:supavisor, :pool, :checkout, :stop, :local],
        &__MODULE__.handle_event/4,
        {self(), ref}
      )

    on_exit(fn -> :telemetry.detach({__MODULE__, ref}) end)

    ref
  end

  def handle_event(_event, measurements, meta, {pid, ref}) do
    send(pid, {ref, measurements, meta})
  end

  defp stop_cluster(cluster_alias, repo_conf) do
    _ =
      Supavisor.stop(
        Supavisor.id(
          type: :cluster,
          tenant: cluster_alias,
          user: repo_conf[:username],
          mode: :transaction,
          db: repo_conf[:database],
          search_path: nil
        )
      )
  end
end
