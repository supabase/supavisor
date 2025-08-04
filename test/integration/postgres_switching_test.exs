defmodule Supavisor.Integration.PostgresSwitchingTest do
  use SupavisorWeb.ConnCase, async: false
  use Supavisor.PostgresCase, async: false

  import Supavisor.Support.Tenants

  @moduletag integration_docker: true

  @postgres_port 7432
  @postgres_user "postgres"
  @postgres_password "postgres"
  @postgres_db "postgres"
  @tenant_name "switching_test_tenant"
  @db_host "localhost"

  setup %{conn: conn} do
    containers = [container_name(15), container_name(16)]
    cleanup_containers(containers)

    jwt = gen_token()

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("authorization", "Bearer " <> jwt)

    on_exit(fn -> cleanup_containers(containers) end)

    {:ok, conn: conn}
  end

  test "PostgreSQL upgrade scenario: 15 -> 16", %{conn: conn} do
    opts = build_opts(15, @tenant_name)

    start_postgres_container(opts)
    create_tenant(conn, opts)
    assert :ok = test_connection(opts)

    stop_postgres_container(opts[:container_name])

    # Ideally, we shouldn't need to terminate the tenant manually here.
    #
    # Instead, Supavisor should detect the version change and either:
    # a) seamlessly handle the "db pool switching" while keeping client
    #    connections available.
    # b) gracefully terminate existing all client handlers
    #
    # Currently, if we don't terminate the tenant (or restart supavisor),
    # we get authentication errors.
    terminate_tenant(conn, @tenant_name)
    Process.sleep(2000)

    opts = build_opts(16, @tenant_name)
    start_postgres_container(opts)

    assert :ok = test_connection(opts)
  end

  defp build_opts(version, external_id) do
    Keyword.merge(postgres_container_opts(version),
      container_name: container_name(version),
      external_id: external_id
    )
  end

  defp postgres_container_opts(version) do
    [
      image: "postgres:#{version}",
      port: @postgres_port,
      user: @postgres_user,
      password: @postgres_password,
      database: @postgres_db,
      hostname: @db_host
    ]
  end

  defp test_connection(opts) do
    connection_opts = connection_opts(opts)

    assert {:ok, conn} = Postgrex.start_link(connection_opts)
    assert {:ok, %{rows: [[_version_string]]}} = Postgrex.query(conn, "SELECT version();", [])

    :ok
  end

  defp container_name(version), do: "test_postgres_#{version}_switching"
end
