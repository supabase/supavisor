defmodule Supavisor.Integration.PsqlTest do
  use Supavisor.DataCase, async: false

  import Supavisor.Asserts

  require Supavisor
  require Supavisor.Protocol.BackendConnection, as: BackendConnection

  @moduletag :integration

  @psql System.find_executable("psql")
  if is_nil(@psql) do
    @moduletag skip: "psql executable is required"
  end

  @tenant "proxy_tenant_psql"

  # `\bind` makes psql send the COPY through the extended protocol.
  test "releases the backend after an extended protocol COPY" do
    psql = start_psql()

    Port.command(psql, """
    BEGIN;
    CREATE TEMP TABLE psql_copy (a int) ON COMMIT DROP;
    COPY psql_copy FROM STDIN \\bind \\g
    1
    2
    \\.
    SELECT count(*) FROM psql_copy;
    COMMIT;
    """)

    output = recv_until(psql, "COMMIT\n")
    assert output =~ "COPY 2\n2\n"

    assert_eventually(10, 100, fn -> elem(:sys.get_state(client_handler()), 0) == :idle end)

    Port.close(psql)
  end

  # psql doesn't read the ErrorResponse of a failed COPY until it has sent its CopyDone, and
  # flushes the data every 8KB, so the COPY fails on the backend while the script is paused.
  test "keeps the backend of a failed COPY until its CopyDone" do
    psql = start_psql()

    Port.command(psql, """
    \\set ON_ERROR_STOP off
    DROP TABLE IF EXISTS psql_copy_fail;
    CREATE TABLE psql_copy_fail (a int);
    COPY psql_copy_fail FROM STDIN;
    oops
    #{String.duplicate("1\n", 10_000)}\
    """)

    recv_until(psql, "CREATE TABLE\n")

    assert_eventually(10, 100, fn ->
      case :sys.get_state(client_handler()) do
        {:busy, %{db_connection: {_pool, db_pid, _sock}}} ->
          {_state, %{backend: backend}} = :sys.get_state(db_pid)
          BackendConnection.backend(backend, :state) == :idle

        _ ->
          false
      end
    end)

    Port.command(psql, """
    \\.
    SELECT 1;
    DROP TABLE psql_copy_fail;
    """)

    output = recv_until(psql, "DROP TABLE\n")
    assert output =~ ~s(invalid input syntax for type integer: "oops")
    assert output =~ ~r/\n1\nDROP TABLE\n$/

    assert_eventually(10, 100, fn -> elem(:sys.get_state(client_handler()), 0) == :idle end)

    Port.close(psql)
  end

  # psql reads the script from stdin, so it stays connected until the port closes.
  defp start_psql do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    env = [
      {~c"PGHOST", ~c"127.0.0.1"},
      {~c"PGPORT", ~c"#{Application.get_env(:supavisor, :proxy_port_transaction)}"},
      {~c"PGDATABASE", ~c"#{db_conf[:database]}"},
      {~c"PGUSER", ~c"#{db_conf[:username]}.#{@tenant}"},
      {~c"PGPASSWORD", ~c"#{db_conf[:password]}"},
      {~c"PGSSLMODE", ~c"disable"}
    ]

    args = ["--no-psqlrc", "--set", "ON_ERROR_STOP=on", "--tuples-only", "-A", "-f", "-"]

    Port.open({:spawn_executable, @psql}, [:binary, :stderr_to_stdout, args: args, env: env])
  end

  defp recv_until(port, suffix, acc \\ "") do
    receive do
      {^port, {:data, data}} ->
        acc = acc <> data
        if String.ends_with?(acc, suffix), do: acc, else: recv_until(port, suffix, acc)
    after
      5000 -> flunk("psql output so far: #{inspect(acc)}")
    end
  end

  defp client_handler do
    key =
      Supavisor.id(
        type: :_,
        tenant: @tenant,
        user: :_,
        mode: :_,
        db: :_,
        search_path: :_,
        upstream_tls: :_
      )

    [pid] = Registry.select(Supavisor.Registry.TenantClients, [{{key, :"$1", :_}, [], [:"$1"]}])
    pid
  end
end
