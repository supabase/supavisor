defmodule Supavisor.ClientHandler.StatsTest do
  use Supavisor.DataCase, async: false

  @moduletag telemetry: true

  setup :external_id

  setup ctx do
    :telemetry.attach(
      {ctx.test, :client},
      [:supavisor, :client, :network, :stat],
      &__MODULE__.handle_event/4,
      self()
    )

    :telemetry.attach(
      {ctx.test, :db},
      [:supavisor, :db, :network, :stat],
      &__MODULE__.handle_event/4,
      self()
    )

    on_exit(fn ->
      :telemetry.detach({ctx.test, :client})
      :telemetry.detach({ctx.test, :db})
    end)
  end

  def handle_event([:supavisor, name, :network, :stat], measurement, meta, pid) do
    send(pid, {:telemetry, {name, measurement, meta}})
  end

  setup ctx do
    conn =
      start_supervised!(
        {Postgrex,
         hostname: "localhost",
         port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
         database: ctx.db,
         username: ctx.user,
         password: "postgres"}
      )

    {:ok, conn: conn}
  end

  describe "client network usage" do
    test "increase on query", ctx do
      external_id = ctx.external_id

      assert {:ok, _} = Postgrex.query(ctx.conn, "SELECT 1", [])

      assert_receive {:telemetry,
                      {:client, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}}

      assert recv > 0
      assert sent > 0
    end

    test "increase on just auth", ctx do
      external_id = ctx.external_id

      assert_receive {:telemetry,
                      {:client, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}}

      assert recv > 0
      assert sent > 0
    end

    test "do not not increase if other tenant is used", ctx do
      external_id = ctx.external_id

      {:ok, other} = external_id(ctx, "another")

      # Cleanup initial data related to sign in
      assert_receive {:telemetry, {:client, _, %{tenant: ^external_id}}}

      other_conn =
        start_supervised!(
          {Postgrex,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
           database: other.db,
           username: other.user,
           password: "postgres"},
          id: :postgrex_another
        )

      assert {:ok, _} = Postgrex.query(other_conn, "SELECT 1", [])

      refute_receive {:telemetry, {:client, _, %{tenant: ^external_id}}}
    end
  end

  describe "server network usage" do
    test "increase on query", ctx do
      external_id = ctx.external_id

      assert {:ok, _} = Postgrex.query(ctx.conn, "SELECT 1", [])

      assert_receive {:telemetry,
                      {:db, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}}

      assert recv > 0
      assert sent > 0
    end

    test "increase on just auth", ctx do
      external_id = ctx.external_id

      assert_receive {:telemetry,
                      {:db, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}}

      assert recv > 0
      assert sent > 0
    end

    test "do not not increase if other tenant is used", ctx do
      external_id = ctx.external_id

      {:ok, other} = external_id(ctx, "another")

      # Cleanup initial data related to sign in
      assert_receive {:telemetry, {:db, _, %{tenant: ^external_id}}}

      other_conn =
        start_supervised!(
          {Postgrex,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
           database: other.db,
           username: other.user,
           password: "postgres"},
          id: :postgrex_another
        )

      assert {:ok, _} = Postgrex.query(other_conn, "SELECT 1", [])

      refute_receive {:telemetry, {:db, _, %{tenant: ^external_id}}}
    end
  end

  defp external_id(_ctx, prefix \\ "default") do
    external_id =
      prefix <> "_" <> String.replace(Ecto.UUID.generate(), "-", "_")

    unboxed(fn ->
      _ = Repo.query("DROP DATABASE IF EXISTS #{external_id}")
      assert {:ok, _} = Repo.query("CREATE DATABASE #{external_id}")
    end)

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
      unboxed(fn ->
        _ = Repo.query("DROP DATABASE IF EXISTS #{external_id}")
      end)
    end)

    {:ok, %{user: "postgres.#{external_id}", db: tenant.db_database, external_id: external_id}}
  end
end
