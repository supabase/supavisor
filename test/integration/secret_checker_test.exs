defmodule Supavisor.Integration.SecretCheckerTest do
  use SupavisorWeb.ConnCase, async: false

  alias Postgrex, as: P

  setup do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)
    tenant_id = "secret_checker_tenant_#{System.unique_integer([:positive])}"

    {:ok, _tenant} =
      Supavisor.Tenants.create_tenant(%{
        db_database: db_conf[:database],
        db_host: to_string(db_conf[:hostname]),
        db_port: db_conf[:port],
        external_id: tenant_id,
        require_user: false,
        auth_query:
          "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1 AND current_database() = '#{db_conf[:database]}'",
        default_parameter_status: %{"server_version" => "15.0"},
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

    %{db_conf: db_conf, tenant_id: tenant_id}
  end

  test "SecretChecker can fetch secrets when pool uses different database", %{
    db_conf: db_conf,
    tenant_id: tenant_id
  } do
    alt_db_name = "supavisor_test_alt_#{System.unique_integer([:positive])}"

    origin =
      start_supervised!(
        {Postgrex,
         hostname: db_conf[:hostname],
         port: db_conf[:port],
         database: db_conf[:database],
         password: db_conf[:password],
         username: db_conf[:username]},
        id: :origin_conn
      )

    P.query!(origin, "CREATE DATABASE #{alt_db_name}", [])

    proxy =
      start_supervised!(
        {Postgrex,
         hostname: db_conf[:hostname],
         port: Application.get_env(:supavisor, :proxy_port_transaction),
         database: alt_db_name,
         password: db_conf[:password],
         username: "#{db_conf[:username]}.#{tenant_id}"},
        id: :proxy_conn
      )

    assert %P.Result{rows: [[1]]} = P.query!(proxy, "SELECT 1", [])

    Process.sleep(100)

    pool_id =
      {{:single, tenant_id}, to_string(db_conf[:username]), :transaction, alt_db_name, nil}

    assert {:ok, %Supavisor.EncryptedSecrets{} = encrypted} =
             Supavisor.SecretChecker.get_secrets(pool_id)

    assert %{user: _} = Supavisor.EncryptedSecrets.decrypt(encrypted)
  end
end
