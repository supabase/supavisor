defmodule Supavisor.Integration.JustInTimeAccessTest do
  use Supavisor.DockerComposeCase, async: false
  use SupavisorWeb.ConnCase

  require(Logger)
  import ExUnit.CaptureLog
  alias Postgrex, as: P

  setup do
    db_conf =
      :supavisor
      |> Application.get_env(Supavisor.Repo)
      |> Keyword.put(:hostname, "localhost")
      |> Keyword.put(:port, "7543")
      |> Keyword.put(:database, "postgres")
      |> Keyword.put(:username, "postgres")
      |> Keyword.put(:password, "postgres")

    %{db_conf: db_conf}
  end

  defp setup_tenant(db_conf) do
    tenant_id = "update_creds_tenant_#{System.unique_integer([:positive])}"

    {:ok, _tenant} =
      Supavisor.Tenants.create_tenant(%{
        db_database: db_conf[:database],
        db_host: to_string(db_conf[:hostname]),
        db_port: db_conf[:port],
        external_id: tenant_id,
        require_user: false,
        auth_query: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
        default_parameter_status: %{"server_version" => "15.0"},
        use_jit: true,
        jit_api_url: "http://localhost:8080/projects/odvmrtdcoyfyvfrdxzsj/database/jit",
        users: [
          %{
            "db_user" => to_string(db_conf[:username]),
            "db_password" => to_string(db_conf[:password]),
            "pool_size" => 3,
            "mode_type" => "transaction",
            "is_manager" => true
          }
        ]
      })

    tenant_id
  end

  test "health check endpoint returns 200" do
    {:ok, response} = api_request(:get, "/health")

    assert response.status == 200
    assert response.body == %{"status" => "healthy"}
  end

  test "valid credentials work directly", %{db_conf: db_conf} do
    tenant_id = setup_tenant(db_conf)

    try do
      assert {:ok, proxy} =
               Postgrex.start_link(
                 hostname: db_conf[:hostname],
                 port: Application.get_env(:supavisor, :proxy_port_transaction),
                 database: db_conf[:database],
                 password: db_conf[:password],
                 username: "#{db_conf[:username]}.#{tenant_id}"
               )

      assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])

      GenServer.stop(proxy)
    after
      Supavisor.Tenants.delete_tenant_by_external_id(tenant_id)
    end
  end

  test "access token fails incorrect token", %{db_conf: db_conf} do
    tenant_id = setup_tenant(db_conf)

    error =
      capture_log(fn ->
        assert_raise DBConnection.ConnectionError, fn ->
          {:ok, proxy} =
            Postgrex.start_link(
              hostname: db_conf[:hostname],
              port: Application.get_env(:supavisor, :proxy_port_transaction),
              database: db_conf[:database],
              password: "sbp_04fee3d26b63d9a3557c72a1b9902cbb84120000",
              username: "#{db_conf[:username]}.#{tenant_id}"
            )

          Postgrex.query!(proxy, "SELECT 1", [])
        end
      end)

    assert error =~ "FATAL 28P01 (invalid_password)"
    assert error =~ "password authentication failed for user \"postgres\""

    Supavisor.Tenants.delete_tenant_by_external_id(tenant_id)
  end

  test "access token fails on bad role token", %{db_conf: db_conf} do
    tenant_id = setup_tenant(db_conf)

    error =
      capture_log(fn ->
        assert_raise DBConnection.ConnectionError, fn ->
          {:ok, proxy} =
            Postgrex.start_link(
              hostname: db_conf[:hostname],
              port: Application.get_env(:supavisor, :proxy_port_transaction),
              database: db_conf[:database],
              password: "sbp_04fee3d26b63d9a3557c72a1b9902cbb84100000",
              username: "supabase_admin.#{tenant_id}"
            )

          Postgrex.query!(proxy, "SELECT 1", [])
        end
      end)

    assert error =~ "FATAL 28P01 (invalid_password)"
    assert error =~ "password authentication failed for user \"supabase_admin\""

    Supavisor.Tenants.delete_tenant_by_external_id(tenant_id)
  end

  test "access token auth works", %{db_conf: db_conf} do
    tenant_id = setup_tenant(db_conf)

    try do
      assert {:ok, proxy} =
               Postgrex.start_link(
                 hostname: db_conf[:hostname],
                 port: Application.get_env(:supavisor, :proxy_port_transaction),
                 database: db_conf[:database],
                 password: "sbp_04fee3d26b63d9a3557c72a1b9902cbb8412c836",
                 username: "#{db_conf[:username]}.#{tenant_id}"
               )

      assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])

      GenServer.stop(proxy)
    after
      Supavisor.Tenants.delete_tenant_by_external_id(tenant_id)
    end
  end
end
