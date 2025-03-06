defmodule Supavisor.ClientHandler.StatsTest do
  use Supavisor.E2ECase, async: false

  @moduletag telemetry: true

  # Listen on Telemetry events
  setup ctx do
    ref = make_ref()

    :telemetry.attach(
      {ctx.test, :client},
      [:supavisor, :client, :network, :stat],
      &__MODULE__.handle_event/4,
      {self(), ref}
    )

    :telemetry.attach(
      {ctx.test, :db},
      [:supavisor, :db, :network, :stat],
      &__MODULE__.handle_event/4,
      {self(), ref}
    )

    on_exit(fn ->
      :telemetry.detach({ctx.test, :client})
      :telemetry.detach({ctx.test, :db})
    end)

    {:ok, telemetry: ref}
  end

  def handle_event([:supavisor, name, :network, :stat], measurement, meta, {pid, ref}) do
    send(pid, {ref, {name, measurement, meta}, Node.self()})
  end

  setup ctx do
    if ctx[:external_id] do
      {:ok, db: "postgres", user: "postgres.#{ctx.external_id}"}
    else
      create_instance([__MODULE__, ctx.line])
    end
  end

  # Connect to the instance
  setup ctx do
    conn =
      start_supervised!(
        {SingleConnection,
         hostname: "localhost",
         port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
         database: ctx.db,
         username: ctx.user,
         password: "postgres"}
      )

    {:ok, conn: conn}
  end

  describe "client network usage" do
    test "increase on query", %{telemetry: telemetry, conn: conn, external_id: external_id} do
      assert {:ok, _} = SingleConnection.query(conn, "SELECT 1")

      assert_receive {^telemetry,
                      {:client, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}, _}

      assert recv > 0
      assert sent > 0
    end

    test "increase on just auth", %{external_id: external_id, telemetry: telemetry} do
      assert_receive {^telemetry,
                      {:client, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}, _}

      assert recv > 0
      assert sent > 0
    end

    test "do not not increase if other tenant is used", %{
      external_id: external_id,
      telemetry: telemetry
    } do
      {:ok, other} = create_instance([__MODULE__, "another"])

      # Cleanup initial data related to sign in
      assert_receive {^telemetry, {:client, _, %{tenant: ^external_id}}, _}

      other_conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
           database: other.db,
           username: other.user,
           password: "postgres"},
          id: :postgrex_another
        )

      assert {:ok, _} = SingleConnection.query(other_conn, "SELECT 1")

      refute_receive {^telemetry, {:client, _, %{tenant: ^external_id}}, _}
    end

    @tag external_id: "metrics_tenant"
    test "another instance do not send events here", %{telemetry: telemetry} = ctx do
      assert {:ok, _pid, node} = Supavisor.Support.Cluster.start_node()

      :erpc.call(node, :telemetry, :attach, [
        {ctx.test, :client},
        [:supavisor, :client, :network, :stat],
        &__MODULE__.handle_event/4,
        self()
      ])

      # Start pool on local node
      _this_conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
           database: ctx.db,
           username: ctx.user,
           password: "postgres"},
          id: :postgrex_this
        )

      stop_supervised!(:postgrex_this)

      # Connect via other node and issue a query
      other_conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :secondary_proxy_port),
           database: ctx.db,
           username: ctx.user,
           password: "postgres"},
          id: :postgrex_another
        )

      assert {:ok, _} = SingleConnection.query(other_conn, "SELECT 1")

      this = Node.self()

      external_id = ctx.external_id

      refute_receive {^telemetry, {:client, _, %{tenant: ^external_id}}, ^node}
      assert_receive {^telemetry, {:client, _, %{tenant: ^external_id}}, ^this}, 10_000
    end
  end

  describe "server network usage" do
    test "increase on query", %{telemetry: telemetry} = ctx do
      external_id = ctx.external_id

      assert {:ok, _} = SingleConnection.query(ctx.conn, "SELECT 1")

      assert_receive {^telemetry,
                      {:db, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}, _}

      assert recv > 0
      assert sent > 0
    end

    test "increase on just auth", %{telemetry: telemetry} = ctx do
      external_id = ctx.external_id

      assert_receive {^telemetry,
                      {:db, %{recv_oct: recv, send_oct: sent}, %{tenant: ^external_id}}, _}

      assert recv > 0
      assert sent > 0
    end

    test "do not not increase if other tenant is used", %{telemetry: telemetry} = ctx do
      external_id = ctx.external_id

      {:ok, other} = create_instance([__MODULE__, "another"])

      # Cleanup initial data related to sign in
      assert_receive {^telemetry, {:db, _, %{tenant: ^external_id}}, _}

      other_conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
           database: other.db,
           username: other.user,
           password: "postgres"},
          id: :postgrex_another
        )

      assert {:ok, _} = SingleConnection.query(other_conn, "SELECT 1")

      refute_receive {^telemetry, {:db, _, %{tenant: ^external_id}}, _}
    end
  end
end
