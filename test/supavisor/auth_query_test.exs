defmodule Supavisor.AuthQueryTest do
  use ExUnit.Case, async: true

  import Supavisor.Asserts
  import ExUnit.CaptureLog

  alias Supavisor.AuthQuery
  alias Supavisor.Errors.AuthQueryError

  defp start_conn do
    db_conf = Application.get_env(:supavisor, Supavisor.Repo)

    {:ok, conn} =
      Postgrex.start_link(
        hostname: db_conf[:hostname],
        port: db_conf[:port],
        database: db_conf[:database],
        password: db_conf[:password],
        username: db_conf[:username]
      )

    conn
  end

  describe "parse_secret/2" do
    test "parses SCRAM-SHA-256 secrets correctly" do
      encoded_stored_key = Base.encode64("storedKey")
      encoded_server_key = Base.encode64("serverKey")
      encoded_salt = Base.encode64("salt")
      secret = "SCRAM-SHA-256$4000:#{encoded_salt}$#{encoded_stored_key}:#{encoded_server_key}"
      user = "user@example.com"

      assert {:ok,
              %Supavisor.Secrets.SASLSecrets{
                digest: "SCRAM-SHA-256",
                iterations: 4000,
                salt: "salt",
                stored_key: "storedKey",
                server_key: "serverKey",
                client_key: nil,
                user: ^user
              }} = AuthQuery.parse_secret(secret, user)
    end

    test "rejects md5 secrets" do
      assert {:error,
              %AuthQueryError{
                reason: :md5_not_supported,
                details: nil,
                code: "EAUTHQUERY"
              }} =
               AuthQuery.parse_secret("md5supersecret", "user")
    end

    test "returns error for unsupported secret format" do
      assert {:error, %AuthQueryError{reason: :unsupported_secret_format}} =
               result = AuthQuery.parse_secret("unsupported_secret", "user")

      assert_valid_error(result)
    end

    test "returns error for malformed SCRAM secret" do
      assert {:error, %AuthQueryError{reason: :parse_error}} =
               result = AuthQuery.parse_secret("SCRAM-SHA-256$malformed", "user")

      assert_valid_error(result)
    end
  end

  describe "fetch_user_secret/3" do
    test "returns error when auth_query is nil" do
      assert {:error, %AuthQueryError{reason: :no_auth_query}} =
               result = AuthQuery.fetch_user_secret(self(), nil, "user")

      assert_valid_error(result)
    end

    test "fetches SCRAM secret successfully" do
      conn = start_conn()
      auth_query = "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1"

      assert {:ok, %Supavisor.Secrets.SASLSecrets{user: "postgres"}} =
               AuthQuery.fetch_user_secret(conn, auth_query, "postgres")

      GenServer.stop(conn)
    end

    test "returns user_not_found for non-existent user" do
      conn = start_conn()
      auth_query = "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1"

      assert {:error, %AuthQueryError{reason: :user_not_found}} =
               result = AuthQuery.fetch_user_secret(conn, auth_query, "nonexistent_user_xyz")

      assert_valid_error(result)
      GenServer.stop(conn)
    end

    test "returns query_failed for invalid query" do
      conn = start_conn()

      assert {:error, %AuthQueryError{reason: :query_failed, details: %Postgrex.Error{}}} =
               result =
               AuthQuery.fetch_user_secret(
                 conn,
                 "SELECT * FROM nonexistent_table WHERE u=$1",
                 "user"
               )

      assert_valid_error(result)
      GenServer.stop(conn)
    end

    test "returns wrong_format when query returns wrong number of columns" do
      conn = start_conn()

      assert {:error, %AuthQueryError{reason: :wrong_format}} =
               result =
               AuthQuery.fetch_user_secret(
                 conn,
                 "SELECT rolname, rolpassword, rolsuper FROM pg_authid WHERE rolname=$1",
                 "postgres"
               )

      assert_valid_error(result)
      GenServer.stop(conn)
    end

    test "returns query_failed for unreachable database" do
      {:ok, conn} =
        Postgrex.start_link(
          hostname: "invalid.nonexistent.host",
          port: 5433,
          database: "test",
          queue_target: 1,
          queue_interval: 4
        )

      assert {:error, %AuthQueryError{reason: :query_failed}} =
               result =
               AuthQuery.fetch_user_secret(
                 conn,
                 "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
                 "user"
               )

      assert_valid_error(result)
      GenServer.stop(conn)
    end
  end

  describe "start_link/2 telemetry:" do
    setup ctx do
      ref = make_ref()

      :telemetry.attach(
        {ctx.test, :auth_query_connection_stop},
        [:supavisor, :auth_query, :connection, :stop],
        fn _event, measurements, metadata, {pid, ref} ->
          send(pid, {ref, measurements, metadata})
        end,
        {self(), ref}
      )

      on_exit(fn -> :telemetry.detach({ctx.test, :auth_query_connection_stop}) end)

      db_conf = Application.get_env(:supavisor, Supavisor.Repo)

      tenant = %Supavisor.Tenants.Tenant{
        db_host: to_string(db_conf[:hostname]),
        db_port: db_conf[:port],
        db_database: db_conf[:database]
      }

      {:ok, ref: ref, db_conf: db_conf, tenant: tenant}
    end

    test "emits connection:stop on successful connection", %{
      ref: ref,
      db_conf: db_conf,
      tenant: tenant
    } do
      manager = %Supavisor.Secrets.ManagerSecrets{
        db_user: to_string(db_conf[:username]),
        db_password: to_string(db_conf[:password])
      }

      {:ok, _conn} = AuthQuery.start_link(tenant, manager)

      assert_receive {^ref, %{duration: duration}, _}
      assert is_integer(duration) && duration > 0
    end
  end

  describe "fetch_user_secret/3 telemetry" do
    setup ctx do
      ref = make_ref()

      :telemetry.attach(
        {ctx.test, :auth_query_query_stop},
        [:supavisor, :auth_query, :query, :stop],
        fn _event, measurements, metadata, {pid, ref} ->
          send(pid, {ref, measurements, metadata})
        end,
        {self(), ref}
      )

      on_exit(fn -> :telemetry.detach({ctx.test, :auth_query_query_stop}) end)
      {:ok, ref: ref}
    end

    test "emits :ok on successful fetch", %{ref: ref} do
      conn = start_conn()

      AuthQuery.fetch_user_secret(
        conn,
        "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
        "postgres"
      )

      assert_receive {^ref, %{duration: duration}, _}
      assert is_integer(duration) && duration > 0
    end

    test "emits :error when query is nil", %{ref: ref} do
      AuthQuery.fetch_user_secret(self(), nil, "user")
      assert_receive {^ref, %{duration: _}, %{status: :error}}
    end

    test "emits :error when user doesn't exist", %{ref: ref} do
      conn = start_conn()

      AuthQuery.fetch_user_secret(
        conn,
        "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
        "nonexistent_user_xyz"
      )

      assert_receive {^ref, %{duration: duration}, %{status: :error}}
      assert is_integer(duration) && duration > 0
    end

    test "emits :error for invalid query", %{ref: ref} do
      conn = start_conn()

      AuthQuery.fetch_user_secret(conn, "SELECT * FROM nonexistent_table WHERE u=$1", "user")

      assert_receive {^ref, %{duration: duration}, %{status: :error}}
      assert is_integer(duration) && duration > 0
    end

    test "auth_query_query_stop logs warning when duration exceeds 1s" do
      conn = start_conn()

      assert capture_log(fn ->
               AuthQuery.fetch_user_secret(
                 conn,
                 "SELECT $1::text, 'dummy'::text FROM pg_sleep(1)",
                 "postgres"
               )
             end) =~ "auth_query took over"
    end

    test "auth_query_query_stop does not log warning for fast queries" do
      conn = start_conn()

      refute capture_log(fn ->
               AuthQuery.fetch_user_secret(
                 conn,
                 "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
                 "postgres"
               )
             end) =~ "auth_query took over"
    end
  end

  describe "connect_and_fetch_user_secret/4 telemetry" do
    setup ctx do
      ref = make_ref()

      :telemetry.attach(
        {ctx.test, :auth_query_connection_stop},
        [:supavisor, :auth_query, :connection, :stop],
        fn _event, measurements, metadata, {pid, ref} ->
          send(pid, {:connection_stop, ref, measurements, metadata})
        end,
        {self(), ref}
      )

      :telemetry.attach(
        {ctx.test, :auth_query_query_stop},
        [:supavisor, :auth_query, :query, :stop],
        fn _event, measurements, metadata, {pid, ref} ->
          send(pid, {:query_stop, ref, measurements, metadata})
        end,
        {self(), ref}
      )

      :telemetry.attach(
        {ctx.test, :auth_query_disconnection},
        [:supavisor, :auth_query, :disconnection],
        fn _event, measurements, metadata, {pid, ref} ->
        send(pid, {:disconnection, ref, measurements, metadata})
        end,
        {self(), ref}
      )

      on_exit(fn ->
        :telemetry.detach({ctx.test, :auth_query_connection_stop})
        :telemetry.detach({ctx.test, :auth_query_query_stop})
      end)

      db_conf = Application.get_env(:supavisor, Supavisor.Repo)

      tenant = %Supavisor.Tenants.Tenant{
        db_host: to_string(db_conf[:hostname]),
        db_port: db_conf[:port],
        db_database: db_conf[:database]
      }

      {:ok, ref: ref, db_conf: db_conf, tenant: tenant}
    end

    test "emits connection:stop and query:stop and :disconnection on successful fetch", %{
      ref: ref,
      tenant: tenant,
      db_conf: db_conf
    } do
      manager = %Supavisor.Secrets.ManagerSecrets{
        db_user: to_string(db_conf[:username]),
        db_password: to_string(db_conf[:password])
      }

      {:ok, _result} =
        AuthQuery.connect_and_fetch_user_secret(
          tenant,
          manager,
          "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1",
          "postgres"
        )

        assert_receive {:connection_stop, ^ref, %{duration: _connection_duration}, _}
        assert_receive {:query_stop, ^ref, %{duration: _query_duration}, _}
        assert_receive {:disconnection, ^ref, %{count: 1}, _}
    end
  end
end
