defmodule Supavisor.Integration.ExternalTest do
  use ExUnit.Case, async: false

  @moduletag integration: true

  setup_all do
    npm =
      get_tool("yarn") || get_tool("npm") || get_tool("bun") ||
        raise "Cannot find neither Yarn nor NPM"

    assert {_, 0} = System.cmd(npm, ~w[install], cd: suite("js"))

    {:ok, npm: npm}
  end

  setup :external_id

  setup ctx do
    if get_tool(ctx.runtime) do
      :ok
    else
      raise "Runtime not available"
    end
  end

  describe "Postgres.js" do
    @describetag library: "postgres.js", suite: "js"

    @tag runtime: "node", mode: "session"
    test "Node session", ctx do
      assert_run(ctx, ~w[postgres/index.js])
    end

    @tag runtime: "node", mode: "transaction"
    test "Node transaction", ctx do
      assert_run(ctx, ~w[postgres/index.js])
    end

    # These currently do not pass
    # @tag runtime: "bun", mode: "session"
    # test "Bun session", ctx do
    #   assert_run ctx, ~w[postgres/index.js], suite: "js"
    # end
    #
    # @tag runtime: "bun", mode: "transaction"
    # test "Bun transaction", ctx do
    #   assert_run ctx, ~w[postgres/index.js], suite: "js"
    # end
    #
    # @tag runtime: "deno", mode: "session"
    # test "Deno session", ctx do
    #   assert_run ctx, ~w[run --allow-all postgres/index.js], suite: "js"
    # end
    #
    # @tag runtime: "deno", mode: "transaction"
    # test "Deno transaction", ctx do
    #   assert_run ctx, ~w[run --allow-all postgres/index.js], suite: "js"
    # end
  end

  defp assert_run(ctx, args, opts \\ []) do
    suite = suite(ctx.suite)

    env =
      [
        {"PGMODE", ctx.mode},
        {"PGDATABASE", ctx.db},
        {"PGHOST", "localhost"},
        {"PGPORT", to_string(port(ctx.mode))},
        {"PGUSER", ctx.user},
        {"PGPASS", "postgres"}
      ] ++ (opts[:env] || [])

    assert {output, code} =
             System.cmd(ctx.runtime, args,
               env: env,
               cd: suite,
               stderr_to_stdout: true
             )

    assert code == 0, output
  end

  ## UTILS

  defp suite(name), do: Path.join(__DIR__, name)

  defp get_tool(name), do: System.find_executable(name)

  defp port("session"), do: Application.fetch_env!(:supavisor, :proxy_port_session)
  defp port("transaction"), do: Application.fetch_env!(:supavisor, :proxy_port_transaction)

  defp external_id(ctx) do
    external_id =
      [ctx.runtime, ctx.library, ctx.mode]
      |> Enum.map_join("_", &String.replace(&1, ~r/\W/, ""))

    # Ensure that there are no leftovers
    _ = Supavisor.Tenants.delete_tenant_by_external_id(external_id)

    _ = Supavisor.Repo.query("DROP DATABASE IF EXISTS #{external_id}")
    assert {:ok, _} = Supavisor.Repo.query("CREATE DATABASE #{external_id}")

    assert {:ok, tenant} =
             Supavisor.Tenants.create_tenant(%{
               default_parameter_status: %{},
               db_host: "localhost",
               db_port: 6432,
               db_database: external_id,
               auth_query: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1;",
               external_id: external_id,
               users: [
                 %{
                   "pool_size" => 15,
                   "db_user" => "postgres",
                   "db_password" => "postgres",
                   "is_manager" => true,
                   "mode_type" => "session"
                 }
               ]
             })

    on_exit(fn ->
      Supavisor.Tenants.delete_tenant(tenant)

      _ = Supavisor.Repo.query("DROP DATABASE IF EXISTS #{external_id}")
    end)

    {:ok, user: "postgres.#{external_id}", db: tenant.db_database, external_id: external_id}
  end
end
