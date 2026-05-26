defmodule Supavisor.Integration.ExternalTest do
  use Supavisor.E2ECase, async: false

  @moduletag integration: true, timeout: 120_000

  setup_all do
    npm =
      get_tool("yarn") || get_tool("npm") || get_tool("bun") ||
        raise "Cannot find neither Yarn nor NPM"

    assert {_, 0} = System.cmd(npm, ~w[install], cd: suite("js"))

    {:ok, npm: npm}
  end

  setup ctx do
    create_instance([ctx.runtime, ctx.library, ctx.mode])
  end

  setup ctx do
    if get_tool(ctx.runtime) do
      :ok
    else
      raise "Runtime not available"
    end
  end

  describe "neondatabase/serverless.js" do
    @describetag library: "serverless.js", suite: "js"

    @tag runtime: "node", mode: "session"
    test "Node session", ctx do
      assert_run(ctx, ~w[neon_serverless/index.js])
    end

    @tag runtime: "node", mode: "transaction"
    test "Node transaction", ctx do
      assert_run(ctx, ~w[neon_serverless/index.js])
    end
  end

  describe "neondatabase/serverless.js — HTTP /sql" do
    @describetag library: "serverless.js (http)", suite: "js"

    setup do
      # The HTTP /sql endpoint is gated behind a global flag plus a
      # per-tenant feature flag; flip both for the duration of the test.
      previous = Application.get_env(:supavisor, :http_sql, [])

      Application.put_env(
        :supavisor,
        :http_sql,
        Keyword.put(previous, :enabled, true)
      )

      tenant = Supavisor.Tenants.get_tenant_by_external_id("dev_tenant")

      previous_flags = tenant.feature_flags || %{}

      {:ok, _} =
        Supavisor.Tenants.update_tenant(tenant, %{
          feature_flags: Map.put(previous_flags, "http_sql", true)
        })

      on_exit(fn ->
        Application.put_env(:supavisor, :http_sql, previous)

        Supavisor.Tenants.update_tenant(tenant, %{feature_flags: previous_flags})
      end)

      :ok
    end

    @tag runtime: "node", mode: "transaction"
    test "Node — drop-in /sql against @neondatabase/serverless", ctx do
      http_endpoint =
        "http://127.0.0.1:#{Application.fetch_env!(:supavisor, SupavisorWeb.Endpoint)[:http][:port]}/sql"

      assert_run(ctx, ~w[neon_http_sql/index.js], env: [{"HTTP_SQL_ENDPOINT", http_endpoint}])
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

    @tag runtime: "bun", mode: "session"
    test "Bun session", ctx do
      assert_run(ctx, ~w[postgres/index.js], suite: "js")
    end

    @tag runtime: "bun", mode: "transaction"
    test "Bun transaction", ctx do
      assert_run(ctx, ~w[postgres/index.js], suite: "js")
    end

    @tag runtime: "deno", mode: "session"
    test "Deno session", ctx do
      assert_run(ctx, ~w[run --allow-all postgres/index.js], suite: "js")
    end

    @tag runtime: "deno", mode: "transaction"
    test "Deno transaction", ctx do
      assert_run(ctx, ~w[run --allow-all postgres/index.js], suite: "js")
    end
  end

  describe "Prisma" do
    @describetag library: "prisma", suite: "js"

    @tag runtime: "node", mode: "session"
    test "Node session", ctx do
      assert_run(ctx, ~w[prisma/index.js])
    end

    @tag runtime: "node", mode: "transaction"
    test "Node transaction", ctx do
      assert_run(ctx, ~w[prisma/index.js])
    end
  end

  defp assert_run(ctx, args, opts \\ []) do
    suite = suite(ctx.suite)

    env =
      [
        # {"NODE_DEBUG", "*"},
        {"PGMODE", ctx.mode},
        {"PGDATABASE", ctx.db},
        {"PGHOST", "127.0.0.1"},
        {"PGPORT", to_string(port(ctx.mode))},
        {"PGUSER", ctx.user},
        {"PGPASS", "postgres"},
        {"FAIL_FAST", to_string(ExUnit.configuration()[:max_failures] != :infinity)}
      ] ++ (opts[:env] || [])

    assert {output, code} =
             System.cmd(ctx.runtime, args,
               env: env,
               cd: suite
               # stderr_to_stdout: true
             )

    assert code == 0, output
  end

  ## UTILS

  defp suite(name), do: Path.join(__DIR__, name)

  defp get_tool(name), do: System.find_executable(name)

  defp port("session"), do: Application.fetch_env!(:supavisor, :proxy_port_session)
  defp port("transaction"), do: Application.fetch_env!(:supavisor, :proxy_port_transaction)
end
