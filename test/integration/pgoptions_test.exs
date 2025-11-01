defmodule Supavisor.Integration.PgoptionsTest do
  use Supavisor.DataCase, async: false

  import ExUnit.CaptureLog

  @tenant "proxy_tenant_pgoptions"

  @moduletag integration: true

  @psql System.find_executable("psql")
  if is_nil(@psql) do
    @moduletag skip: "psql executable is required for PGOPTIONS integration checks"
  end

  setup do
    repo_conf = Application.fetch_env!(:supavisor, Repo)
    port = Application.fetch_env!(:supavisor, :proxy_port_transaction)

    {:ok,
     %{
       psql: @psql,
       port: port,
       db: repo_conf[:database],
       user: "#{repo_conf[:username]}.#{@tenant}"
     }}
  end

  test "PGOPTIONS --search_path=schemaA,schemaB", ctx do
    result =
      run_psql!(ctx, "SHOW search_path;", pgoptions: "--search_path=schemaA,schemaB")

    assert result == "schemaA,schemaB"
  end

  test "PGOPTIONS -c search_path=custom-schema", ctx do
    result =
      run_psql!(ctx, "SHOW search_path;", pgoptions: "-c search_path=custom-schema")

    assert result == "custom-schema"
  end

  test "PGOPTIONS --search_path schema with whitespaces", ctx do
    result =
      run_psql!(ctx, "SHOW search_path;", pgoptions: "--search_path=schemaA,\\ schemaB")

    assert result == "schemaA, schemaB"
  end

  test "PGOPTIONS does not allow injecting additional -c flags after the --search_path", ctx do
    default_timeout = run_psql!(ctx, "SHOW work_mem;")

    injected_timeout =
      run_psql!(ctx, "SHOW work_mem;", pgoptions: "--search_path=public -c work_mem=2047GB")

    assert injected_timeout == default_timeout
    assert injected_timeout != "2047GB"
  end

  test "Malformed option is ignored", ctx do
    log =
      capture_log([level: :debug], fn ->
        assert run_psql!(ctx, "SHOW search_path;",
                 pgoptions: "--search_path=OK -malformed-option"
               ) == "OK"
      end)

    assert log =~ ~s(StartupOptions: ignored token "-malformed-option")
  end

  test "PGOPTIONS log_level switches Supavisor process log level", ctx do
    log =
      capture_log([level: :debug], fn ->
        run_psql!(ctx, "SELECT 1;", pgoptions: "--log_level=notice")
      end)

    assert log =~ "Setting log level to :notice"
  end

  # TODO: https://github.com/supabase/supavisor/issues/343
  @tag skip: "known issue #343"
  test "PGOPTIONS -c application_name applies to upstream application_name", ctx do
    result =
      run_psql!(ctx, "SHOW application_name;", pgoptions: "-c application_name=from_options")

    assert result == "from_options"
  end

  # TODO: handle Supavisor startup failures instead of restarts
  @tag skip: "known issue: keeps reconnecting on invalid PGOPTIONS search_path"
  test "PGOPTIONS --search_path invalid syntax", ctx do
    log =
      capture_log([level: :debug], fn ->
        assert_raise ExUnit.AssertionError,
                     ~r/(invalid value for parameter \"search_path\"|server closed the connection unexpectedly)/,
                     fn ->
                       run_psql!(ctx, "SHOW search_path;",
                         pgoptions: "--search_path=,--invalid-syntax--;("
                       )
                     end
      end)

    occurrences =
      Regex.scan(~r/"SFATAL", "VFATAL", "C22023", "Minvalid value for parameter/, log)
      |> length()

    assert occurrences == 1
  end

  defp run_psql!(ctx, sql, opts \\ []) do
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

    {output, status} =
      System.cmd(ctx.psql, args,
        env: env,
        stderr_to_stdout: true
      )

    assert status == 0, output

    output
    |> String.trim()
    |> String.split("\n")
    |> List.last()
    |> String.trim()
  end

  defp maybe_put_pgoptions(env, nil), do: env
  defp maybe_put_pgoptions(env, ""), do: env
  defp maybe_put_pgoptions(env, value), do: [{"PGOPTIONS", value} | env]
end
