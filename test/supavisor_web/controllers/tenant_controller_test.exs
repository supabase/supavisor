defmodule SupavisorWeb.TenantControllerTest do
  use SupavisorWeb.ConnCase, async: false

  import Supavisor.TenantsFixtures
  import ExUnit.CaptureLog

  alias Supavisor.Tenants.Tenant

  @user_valid_attrs %{
    "db_user_alias" => "some_db_user",
    "db_user" => "some db_user",
    "db_password" => "some db_password",
    "pool_size" => 3,
    "mode_type" => "transaction"
  }

  @create_attrs %{
    db_database: "some db_database",
    db_host: "some db_host",
    db_port: 42,
    external_id: "dev_tenant",
    require_user: true,
    default_parameter_status: %{"server_version" => "15.0"},
    users: [@user_valid_attrs]
  }
  @update_attrs %{
    db_database: "some updated db_database",
    db_host: "some updated db_host",
    db_port: 43,
    external_id: "dev_tenant",
    require_user: true,
    allow_list: ["71.209.249.38/32"],
    users: [@user_valid_attrs]
  }
  @update_upstream_attrs %{
    upstream_tls_ca: "-----BEGIN CERTIFICATE-----\nsomecert\n-----END CERTIFICATE-----"
  }
  @update_invalid_upstream_attrs %{
    upstream_tls_ca: "-----BEGIN"
  }
  @invalid_upstream_verify_attrs %{
    upstream_ssl: true,
    upstream_verify: "peer"
  }
  @invalid_attrs %{
    db_database: nil,
    db_host: nil,
    db_port: nil,
    external_id: nil
  }
  @auth_query_tenant_attrs %{
    db_database: "auth_query_db",
    db_host: "auth_query_host",
    db_port: 5432,
    external_id: "auth_query_tenant",
    require_user: false,
    auth_query: "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
    default_parameter_status: %{"server_version" => "15.0"},
    users: [
      %{
        "db_user" => "manager_user",
        "db_password" => "old_password",
        "pool_size" => 3,
        "mode_type" => "transaction",
        "is_manager" => true
      }
    ]
  }
  @update_auth_credentials_attrs %{
    db_user: "manager_user",
    db_password: "new_password"
  }

  setup %{conn: conn} do
    :meck.expect(Supavisor.Helpers, :check_creds_get_ver, fn _ -> {:ok, "0.0"} end)

    jwt = gen_token()

    new_conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header(
        "authorization",
        "Bearer " <> jwt
      )

    blocked_jwt = gen_token("invalid")

    blocked_conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header(
        "authorization",
        "Bearer " <> blocked_jwt
      )

    on_exit(fn ->
      :meck.unload(Supavisor.Helpers)
    end)

    {:ok, conn: new_conn, blocked_conn: blocked_conn}
  end

  describe "create tenant" do
    test "renders tenant when data is valid", %{conn: conn} do
      assert %{data: %{external_id: "dev_tenant"}} =
               conn
               |> put(~p"/api/tenants/dev_tenant", tenant: @create_attrs)
               |> json_response(201)
               |> assert_schema("TenantData")
    end

    test "renders errors when data is invalid", %{conn: conn} do
      assert %{} !=
               conn
               |> put(~p"/api/tenants/dev_tenant", tenant: @invalid_attrs)
               |> json_response(422)
               |> assert_schema("UnprocessablyEntity")
    end
  end

  describe "create tenant with blocked ip" do
    test "renders tenant when data is valid", %{blocked_conn: blocked_conn} do
      blocked_conn = put(blocked_conn, ~p"/api/tenants/dev_tenant", tenant: @create_attrs)

      assert blocked_conn.status == 403
    end
  end

  describe "update tenant" do
    setup [:create_tenant]

    test "renders tenant when data is valid", %{
      conn: conn,
      tenant: %Tenant{external_id: external_id}
    } do
      set_cache(external_id)

      assert %{data: %{external_id: ^external_id}} =
               put(conn, ~p"/api/tenants/#{external_id}", tenant: @update_attrs)
               |> json_response(200)
               |> assert_schema("TenantData")

      check_cache(external_id)

      assert %{
               data: %{
                 external_id: ^external_id,
                 db_database: "some updated db_database",
                 db_host: "some updated db_host",
                 db_port: 43,
                 allow_list: ["71.209.249.38/32"]
               }
             } =
               conn
               |> get(~p"/api/tenants/#{external_id}")
               |> json_response(200)
               |> assert_schema("TenantData")
    end

    test "renders tenant when data is valid and coverts cert to pem format", %{
      conn: conn,
      tenant: %Tenant{external_id: external_id}
    } do
      assert %{data: %{external_id: external_id}} =
               conn
               |> put(~p"/api/tenants/#{external_id}", tenant: @update_upstream_attrs)
               |> json_response(200)
               |> assert_schema("TenantData")

      assert Supavisor.Tenants.get_tenant_by_external_id(external_id).upstream_tls_ca ==
               <<178, 137, 158, 113, 234, 237>>
    end

    test "renders error when upstream_tls_ca is invalid", %{
      conn: conn,
      tenant: %Tenant{external_id: external_id}
    } do
      assert %{
               "error" =>
                 "Invalid 'upstream_tls_ca' certificate, reason: :cant_decode_certificate"
             } ==
               conn
               |> put(~p"/api/tenants/#{external_id}", tenant: @update_invalid_upstream_attrs)
               |> json_response(400)
               |> assert_schema("NotFound")
    end

    test "renders errors when data is invalid", %{conn: conn, tenant: tenant} do
      assert %{
               "error" =>
                 "Invalid 'upstream_verify' value, 'peer' is not allowed without certificate"
             } ==
               conn
               |> put(~p"/api/tenants/#{tenant}", tenant: @invalid_upstream_verify_attrs)
               |> json_response(400)
               |> assert_schema("NotFound")
    end

    test "renders errors", %{conn: conn, tenant: tenant} do
      assert %{} !=
               conn
               |> put(~p"/api/tenants/#{tenant}", tenant: @invalid_attrs)
               |> json_response(422)
               |> assert_schema("UnprocessablyEntity")
    end

    test "triggers Supavisor.stop/2", %{
      conn: conn,
      tenant: %Tenant{external_id: external_id}
    } do
      msg = "Stop #{@update_attrs.external_id}"

      assert capture_log(fn ->
               put(conn, ~p"/api/tenants/#{external_id}", tenant: @update_attrs)
             end) =~ msg
    end
  end

  describe "delete tenant" do
    setup [:create_tenant]

    test "deletes chosen tenant", %{conn: conn, tenant: %Tenant{external_id: external_id}} do
      set_cache(external_id)
      conn = delete(conn, ~p"/api/tenants/#{external_id}")
      check_cache(external_id)
      assert response(conn, 204) == ""
    end
  end

  describe "get tenant" do
    setup [:create_tenant]

    test "returns 404 not found for non-existing tenant", %{conn: conn} do
      non_existing_tenant_id = "non_existing_tenant_id"

      assert %{"error" => "not found"} ==
               get(conn, ~p"/api/tenants/#{non_existing_tenant_id}")
               |> json_response(404)
               |> assert_schema("NotFound")
    end
  end

  describe "update auth credentials" do
    test "successfully updates credentials for auth_query tenant (require_user: false)", %{
      conn: conn
    } do
      {:ok, auth_tenant} = Supavisor.Tenants.create_tenant(@auth_query_tenant_attrs)
      external_id = auth_tenant.external_id

      :meck.expect(Supavisor, :update_secret_checker_credentials_global, fn _tenant,
                                                                            _user,
                                                                            _password ->
        [{:ok, :ok}]
      end)

      on_exit(fn ->
        :meck.unload(Supavisor)
      end)

      assert "" ==
               conn
               |> post(
                 ~p"/api/tenants/#{external_id}/update_auth_credentials",
                 @update_auth_credentials_attrs
               )
               |> response(204)

      updated_tenant = Supavisor.Tenants.get_tenant_by_external_id(external_id)
      manager = Enum.find(updated_tenant.users, & &1.is_manager)
      assert manager.db_password == "new_password"
    end

    test "rejects update for require_user: true tenant", %{conn: conn} do
      {:ok, tenant} = Supavisor.Tenants.create_tenant(@create_attrs)

      assert %{"error" => "Cannot update credentials for tenants with require_user: true"} ==
               conn
               |> post(
                 ~p"/api/tenants/#{tenant.external_id}/update_auth_credentials",
                 @update_auth_credentials_attrs
               )
               |> json_response(400)
               |> assert_schema("NotFound")
    end

    test "returns 404 for non-existent tenant", %{conn: conn} do
      assert %{"error" => "not found"} ==
               conn
               |> post(
                 ~p"/api/tenants/non_existent_tenant/update_auth_credentials",
                 @update_auth_credentials_attrs
               )
               |> json_response(404)
               |> assert_schema("NotFound")
    end

    test "clears cache when updating credentials", %{conn: conn} do
      {:ok, auth_tenant} = Supavisor.Tenants.create_tenant(@auth_query_tenant_attrs)
      external_id = auth_tenant.external_id

      :meck.expect(Supavisor, :update_secret_checker_credentials_global, fn _tenant,
                                                                            _user,
                                                                            _password ->
        [{:ok, :ok}]
      end)

      on_exit(fn ->
        :meck.unload(Supavisor)
      end)

      set_cache(external_id)

      assert "" ==
               conn
               |> post(
                 ~p"/api/tenants/#{external_id}/update_auth_credentials",
                 @update_auth_credentials_attrs
               )
               |> response(204)

      check_cache(external_id)
    end

    test "accepts only db_user and db_password fields", %{conn: conn} do
      {:ok, auth_tenant} = Supavisor.Tenants.create_tenant(@auth_query_tenant_attrs)
      external_id = auth_tenant.external_id

      :meck.expect(Supavisor, :update_secret_checker_credentials_global, fn _tenant,
                                                                            _user,
                                                                            _password ->
        [{:ok, :ok}]
      end)

      on_exit(fn ->
        :meck.unload(Supavisor)
      end)

      params_with_extra_fields = %{
        db_user: "new_manager_user",
        db_password: "new_secure_password",
        pool_size: 999,
        is_manager: false,
        mode_type: "session"
      }

      assert "" ==
               conn
               |> post(
                 ~p"/api/tenants/#{external_id}/update_auth_credentials",
                 params_with_extra_fields
               )
               |> response(204)

      updated_tenant = Supavisor.Tenants.get_tenant_by_external_id(external_id)
      manager = Enum.find(updated_tenant.users, & &1.is_manager)
      assert manager.db_user == "new_manager_user"
      assert manager.db_password == "new_secure_password"
      assert manager.pool_size == 3
      assert manager.is_manager == true
      assert manager.mode_type == :transaction
    end

    test "returns validation error when db_user is missing", %{conn: conn} do
      {:ok, auth_tenant} = Supavisor.Tenants.create_tenant(@auth_query_tenant_attrs)
      external_id = auth_tenant.external_id

      invalid_params = %{db_password: "new_password"}

      assert %{"errors" => _} =
               conn
               |> post(~p"/api/tenants/#{external_id}/update_auth_credentials", invalid_params)
               |> json_response(422)
    end

    test "returns validation error when db_password is missing", %{conn: conn} do
      {:ok, auth_tenant} = Supavisor.Tenants.create_tenant(@auth_query_tenant_attrs)
      external_id = auth_tenant.external_id

      invalid_params = %{db_user: "new_user"}

      assert %{"errors" => _} =
               conn
               |> post(~p"/api/tenants/#{external_id}/update_auth_credentials", invalid_params)
               |> json_response(422)
    end

    test "returns validation error when both fields are missing", %{conn: conn} do
      {:ok, auth_tenant} = Supavisor.Tenants.create_tenant(@auth_query_tenant_attrs)
      external_id = auth_tenant.external_id

      assert %{"errors" => _} =
               conn
               |> post(~p"/api/tenants/#{external_id}/update_auth_credentials", %{})
               |> json_response(422)
    end
  end

  describe "list bans" do
    setup do
      :ets.delete_all_objects(Supavisor.CircuitBreaker)
      :ok
    end

    test "renders a list of bans applied to the tenant", %{conn: conn} do
      {:ok, tenant} = Supavisor.Tenants.create_tenant(@create_attrs)
      external_id = tenant.external_id

      Supavisor.CircuitBreaker.record_failure(external_id, :db_connection)

      for _ <- 1..10 do
        Supavisor.CircuitBreaker.record_failure(external_id, :get_secrets)
        Supavisor.CircuitBreaker.record_failure(external_id, :auth_error)
      end

      assert {:error, :circuit_open, auth_blocked_until} =
               Supavisor.CircuitBreaker.check(external_id, :auth_error)

      assert {:error, :circuit_open, get_secrets_blocked_until} =
               Supavisor.CircuitBreaker.check(external_id, :get_secrets)

      assert %_{
               data: [
                 %_{
                   operation: "auth_error",
                   blocked_until: ^auth_blocked_until
                 },
                 %_{
                   operation: "get_secrets",
                   blocked_until: ^get_secrets_blocked_until
                 }
               ]
             } =
               conn
               |> get(~p"/api/tenants/#{external_id}/bans")
               |> json_response(200)
               |> assert_schema("BanList")
    end

    test "returns an empty list when there are no bans applied to the tenant", %{conn: conn} do
      {:ok, tenant} = Supavisor.Tenants.create_tenant(@create_attrs)
      external_id = tenant.external_id

      assert %_{data: []} =
               conn
               |> get(~p"/api/tenants/#{external_id}/bans")
               |> json_response(200)
               |> assert_schema("BanList")
    end

    test "returns 404 for non-existent tenant", %{conn: conn} do
      tenant_id = "non_existent_tenant"

      assert %{"error" => "not found"} ==
               conn
               |> get(~p"/api/tenants/#{tenant_id}/bans")
               |> json_response(404)
               |> assert_schema("NotFound")
    end
  end

  describe "clear ban" do
    setup do
      :ets.delete_all_objects(Supavisor.CircuitBreaker)
      :ok
    end

    test "clears a specific ban and returns remaining bans", %{conn: conn} do
      {:ok, tenant} = Supavisor.Tenants.create_tenant(@create_attrs)
      external_id = tenant.external_id

      for _ <- 1..10 do
        Supavisor.CircuitBreaker.record_failure(external_id, :auth_error)
        Supavisor.CircuitBreaker.record_failure(external_id, :get_secrets)
      end

      assert Supavisor.Tenants.list_tenant_bans(external_id) |> length() == 2

      assert %_{data: _remaining_bans = [%_{operation: "get_secrets"}]} =
               post(
                 conn,
                 ~p"/api/tenants/#{external_id}/bans/auth_error/clear"
               )
               |> json_response(200)
               |> assert_schema("BanList")

      assert :ok == Supavisor.CircuitBreaker.check(external_id, :auth_error)
    end

    test "returns 404 when tenant does not exist", %{conn: conn} do
      assert conn
             |> post(~p"/api/tenants/nonexistent/bans/auth_error/clear")
             |> json_response(404)
             |> assert_schema("NotFound")
    end

    test "returns 400 for invalid operation", %{conn: conn} do
      {:ok, tenant} = Supavisor.Tenants.create_tenant(@create_attrs)

      assert conn
             |> post(~p"/api/tenants/#{tenant.external_id}/bans/invalid_op/clear")
             |> json_response(400)
             |> assert_schema("BadRequest")
    end

    test "returns empty list when clearing the last ban", %{conn: conn} do
      {:ok, tenant} = Supavisor.Tenants.create_tenant(@create_attrs)
      external_id = tenant.external_id

      # Create single ban
      for _ <- 1..10 do
        Supavisor.CircuitBreaker.record_failure(external_id, :auth_error)
      end

      # Clear the only ban
      conn = post(conn, ~p"/api/tenants/#{external_id}/bans/auth_error/clear")

      assert %{"data" => []} = json_response(conn, 200)
    end
  end

  describe "health endpoint" do
    test "returns 204 when all health checks pass", %{conn: conn} do
      assert "" ==
               conn
               |> get(~p"/api/health")
               |> response(204)
    end

    test "returns 503 with failed checks when health checks fail", %{conn: conn} do
      :meck.expect(Supavisor.Health, :database_reachable?, fn -> false end)
      on_exit(fn -> :meck.unload(Supavisor.Health) end)

      assert %{status: "unhealthy", failed_checks: ["database_reachable"], timestamp: timestamp} =
               conn
               |> get(~p"/api/health")
               |> json_response(503)
               |> assert_schema("ServiceUnavailable")

      assert {:ok, _datetime, _offset} = DateTime.from_iso8601(timestamp)
    end
  end

  defp create_tenant(_) do
    tenant = tenant_fixture()
    %{tenant: tenant}
  end

  defp set_cache(external_id) do
    Supavisor.Tenants.get_user_cache(:single, "user", external_id, nil)
    Supavisor.Tenants.get_tenant_cache(external_id, nil)
  end

  defp check_cache(external_id) do
    assert {:ok, nil} =
             Cachex.get(Supavisor.Cache, {:user_cache, :single, "user", external_id, nil})

    assert {:ok, nil} = Cachex.get(Supavisor.Cache, {:tenant_cache, external_id, nil})
  end

  defp gen_token(secret \\ Application.fetch_env!(:supavisor, :metrics_jwt_secret)) do
    Supavisor.Jwt.Token.gen!(secret)
  end
end
