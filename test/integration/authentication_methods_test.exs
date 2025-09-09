defmodule Supavisor.Integration.AuthenticationMethodsTest do
  use SupavisorWeb.ConnCase, async: false
  use Supavisor.PostgresCase, async: false

  import Supavisor.Support.Tenants

  @moduletag integration_docker: true

  @auth_configs %{
    "scram-sha-256": [
      hostname: "localhost",
      port: 6433,
      database: "postgres",
      username: "postgres",
      password: "postgres"
    ],
    password: [
      hostname: "localhost",
      port: 6434,
      database: "postgres",
      username: "postgres",
      password: "postgres",
      volume: "./dev/postgres/password/etc/postgresql/pg_hba.conf:/etc/postgresql/pg_hba.conf",
      environment: "--auth-host=password"
    ]
    # md5: [
    #   hostname: "localhost",
    #   port: 6434,
    #   database: "postgres",
    #   username: "postgres",
    #   password: "postgres",
    #   volume: "./dev/postgres/md5/etc/postgresql/pg_hba.conf:/etc/postgresql/pg_hba.conf",
    #   environment: "--auth-host=md5"
    # ]
  }

  for {key, auth_config} <- @auth_configs do
    describe "#{key}" do
      setup %{conn: conn} do
        external_id = unquote(key)
        container_name = container_name(external_id)

        cleanup_containers(container_name)

        jwt = gen_token()

        conn =
          conn
          |> put_req_header("accept", "application/json")
          |> put_req_header("authorization", "Bearer " <> jwt)

        on_exit(fn -> cleanup_containers(container_name) end)

        {:ok, conn: conn, container_name: container_name, external_id: external_id}
      end

      test "starts postgres and connects through proxy", %{
        conn: conn,
        container_name: container_name,
        external_id: external_id
      } do
        opts =
          Keyword.merge(unquote(auth_config),
            container_name: container_name,
            external_id: external_id
          )

        start_postgres_container(opts)
        create_tenant(conn, opts)

        assert :ok = test_connection(opts)

        stop_postgres_container(container_name)
        terminate_tenant(conn, external_id)
      end
    end
  end

  defp test_connection(opts) do
    connection_opts = connection_opts(opts)

    assert {:ok, conn} = Postgrex.start_link(connection_opts)
    assert {:ok, %{rows: [[_version_string]]}} = Postgrex.query(conn, "SELECT version();", [])

    :ok
  end

  defp container_name(internal_id), do: "supavisor-db-#{internal_id}"
end
