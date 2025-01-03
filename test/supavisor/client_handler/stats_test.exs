defmodule Supavisor.ClientHandler.StatsTest do
  use Supavisor.E2ECase, async: false

  @moduletag telemetry: true

  # Listen on Telemetry events
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
    create_instance([__MODULE__, ctx.line])
  end

  # Connect to the instance
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

      {:ok, other} = create_instance([__MODULE__, "another"])

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

      {:ok, other} = create_instance([__MODULE__, "another"])

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
end
