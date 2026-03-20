defmodule Supavisor.PromEx.Plugins.TenantTest do
  use Supavisor.E2ECase, async: false

  require Supavisor
  import ExUnit.CaptureLog
  alias Supavisor.PromEx.Plugins.Tenant
  alias Supavisor.PromEx.Plugins.TenantTest.FakePool

  @moduletag telemetry: true

  describe "polling_metrics/1" do
    test "properly exports metric" do
      for polling_metric <- Tenant.polling_metrics([]) do
        assert %PromEx.MetricTypes.Polling{metrics: [_ | _]} = polling_metric
        {m, f, a} = polling_metric.measurements_mfa
        assert function_exported?(m, f, length(a))

        for telemetry_metric <- polling_metric.metrics do
          assert Enum.any?(
                   [
                     Telemetry.Metrics.Distribution,
                     Telemetry.Metrics.Counter,
                     Telemetry.Metrics.LastValue,
                     Telemetry.Metrics.Sum
                   ],
                   fn struct -> is_struct(telemetry_metric, struct) end
                 )

          assert telemetry_metric.description
        end
      end
    end

    test "uses poll rate option" do
      for polling_metric <- Tenant.polling_metrics(poll_rate: 1000) do
        assert %{poll_rate: 1000} = polling_metric
      end
    end
  end

  describe "client_handler state transitions" do
    setup ctx do
      create_instance([__MODULE__, ctx.line])
    end

    test "emits state transition events", ctx do
      tenant = ctx.external_id
      ref = attach_handler([:supavisor, :client_handler, :state])

      start_supervised!(
        {SingleConnection,
         hostname: "localhost",
         port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
         database: ctx.db,
         username: ctx.user,
         password: "postgres"}
      )

      assert_receive {^ref, {[:supavisor, :client_handler, :state], %{duration: _}, meta}}
      assert %{from_state: :handshake, to_state: :auth_scram_first_wait, tenant: ^tenant} = meta

      assert_receive {^ref, {[:supavisor, :client_handler, :state], %{duration: _}, meta}}

      assert %{
               from_state: :auth_scram_first_wait,
               to_state: :auth_scram_final_wait,
               tenant: ^tenant
             } = meta

      assert_receive {^ref, {[:supavisor, :client_handler, :state], %{duration: _}, meta}}
      assert %{from_state: :auth_scram_final_wait, to_state: :connecting, tenant: ^tenant} = meta

      assert_receive {^ref, {[:supavisor, :client_handler, :state], %{duration: _}, meta}}
      assert %{from_state: :connecting, to_state: :idle, tenant: ^tenant} = meta
    end
  end

  describe "execute_client_connections_lifetime" do
    setup ctx do
      create_instance([__MODULE__, ctx.line])
    end

    test "emits event for active client connections", ctx do
      start_supervised!(
        {SingleConnection,
         hostname: "localhost",
         port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
         database: ctx.db,
         username: ctx.user,
         password: "postgres"}
      )

      ref = attach_handler([:supavisor, :client, :connection, :lifetime])
      assert :ok = Tenant.execute_client_connections_lifetime()

      assert_receive {^ref, {[:supavisor, :client, :connection, :lifetime], measurement, meta}}

      assert %{lifetime: lifetime} = measurement
      assert lifetime >= 0

      assert meta == %{
               tenant: ctx.db,
               user: String.split(ctx.user, ".") |> List.first(),
               mode: :transaction,
               type: :single,
               db_name: ctx.db,
               search_path: nil
             }
    end
  end

  describe "execute_tenant_metrics/0" do
    test "aggregates clients with different upstream_tls into one count" do
      base_id =
        Supavisor.id(
          type: :single,
          tenant: "metrics_tls_test",
          user: "test_user",
          mode: :transaction,
          db: "test_db",
          search_path: nil,
          upstream_tls: false
        )

      tls_id = Supavisor.id(base_id, upstream_tls: true)

      # Register 3 clients without TLS and 2 with TLS
      for {id, i} <- Enum.with_index([base_id, base_id, base_id, tls_id, tls_id]) do
        start_supervised!(
          {Task,
           fn ->
             Registry.register(Supavisor.Registry.TenantClients, id, [])
             Process.sleep(:infinity)
           end},
          id: :"client_#{i}"
        )
      end

      ref = attach_handler([:supavisor, :connections])
      Tenant.execute_tenant_metrics()

      assert_receive {^ref, {[:supavisor, :connections], %{active: 5}, meta}}

      assert meta == %{
               tenant: "metrics_tls_test",
               user: "test_user",
               mode: :transaction,
               type: :single,
               db_name: "test_db",
               search_path: nil
             }

      refute_receive {^ref, {[:supavisor, :connections], %{active: 3}, _}}
      refute_receive {^ref, {[:supavisor, :connections], %{active: 2}, _}}
    end
  end

  describe "execute_tenant_proxy_metrics/0" do
    test "aggregates proxy clients with different upstream_tls into one count" do
      base_id =
        Supavisor.id(
          type: :single,
          tenant: "proxy_metrics_tls_test",
          user: "test_user",
          mode: :transaction,
          db: "test_db",
          search_path: nil,
          upstream_tls: false
        )

      tls_id = Supavisor.id(base_id, upstream_tls: true)

      for {id, i} <- Enum.with_index([base_id, base_id, tls_id]) do
        start_supervised!(
          {Task,
           fn ->
             Registry.register(Supavisor.Registry.TenantProxyClients, id, [])
             Process.sleep(:infinity)
           end},
          id: :"proxy_client_#{i}"
        )
      end

      ref = attach_handler([:supavisor, :proxy, :connections])
      Tenant.execute_tenant_proxy_metrics()

      assert_receive {^ref, {[:supavisor, :proxy, :connections], %{active: 3}, meta}}

      assert meta == %{
               tenant: "proxy_metrics_tls_test",
               user: "test_user",
               mode: :transaction,
               type: :single,
               db_name: "test_db",
               search_path: nil
             }

      refute_receive {^ref, {[:supavisor, :proxy, :connections], %{active: 2}, _}}
      refute_receive {^ref, {[:supavisor, :proxy, :connections], %{active: 1}, _}}
    end
  end

  describe "execute_pool_metrics/0" do
    setup ctx do
      create_instance([__MODULE__, ctx.line])
    end

    test "reports idle: 1 after transaction query completes", ctx do
      conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
           database: ctx.db,
           username: ctx.user,
           password: "postgres"}
        )

      {:ok, _} = SingleConnection.query(conn, "SELECT 1")

      ref = attach_handler([:supavisor, :pool, :connections])
      Tenant.execute_pool_metrics()

      assert_receive {^ref, {[:supavisor, :pool, :connections], %{idle: 1, checked_out: 0}, meta}}

      assert meta == %{
               tenant: ctx.db,
               user: String.split(ctx.user, ".") |> List.first(),
               mode: :transaction,
               type: :single,
               db_name: ctx.db,
               search_path: nil
             }
    end

    test "reports checked_out: 1 during an open transaction", ctx do
      conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_transaction),
           database: ctx.db,
           username: ctx.user,
           password: "postgres"}
        )

      {:ok, _} = SingleConnection.query(conn, "BEGIN")

      ref = attach_handler([:supavisor, :pool, :connections])
      Tenant.execute_pool_metrics()

      assert_receive {^ref, {[:supavisor, :pool, :connections], %{idle: 0, checked_out: 1}, meta}}

      assert meta.mode == :transaction
      assert meta.tenant == ctx.db
    end

    test "reports checked_out: 1 for an active session connection", ctx do
      conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_session),
           database: ctx.db,
           username: ctx.user,
           password: "postgres"}
        )

      {:ok, _} = SingleConnection.query(conn, "SELECT 1")

      ref = attach_handler([:supavisor, :pool, :connections])
      Tenant.execute_pool_metrics()

      assert_receive {^ref, {[:supavisor, :pool, :connections], %{idle: 0, checked_out: 1}, meta}}

      assert meta.mode == :session
      assert meta.tenant == ctx.db
    end

    test "logs and error if pool status request times out", ctx do
      conn =
        start_supervised!(
          {SingleConnection,
           hostname: "localhost",
           port: Application.fetch_env!(:supavisor, :proxy_port_session),
           database: ctx.db,
           username: ctx.user,
           password: "postgres"}
        )

      {:ok, _} = SingleConnection.query(conn, "SELECT pg_sleep(2)")

      pid =
        Supavisor.get_local_pool(
          Supavisor.id(
            type: :single,
            tenant: ctx.external_id,
            user: String.split(ctx.user, ".") |> List.first(),
            mode: :session,
            db: ctx.external_id
          )
        )

      :sys.suspend(pid)

      ref = attach_handler([:supavisor, :pool, :connections])

      capture_log(fn -> Tenant.execute_pool_metrics() end) =~
        "Failed to execute pool metrics: time out"

      refute_receive {^ref, {[:supavisor, :pool, :connections], _, _}}
    end

    test "aggregates multiple pools with the same id into one event" do
      id =
        Supavisor.id(
          type: :single,
          tenant: "pool_cluster_test",
          user: "test_user",
          mode: :transaction,
          db: "test_db",
          search_path: nil,
          upstream_tls: false
        )

      # Simulate cluster mode: two pools registered under the same canonical id
      # but with different replica_type and pool_index (as TenantSupervisor does).
      for {replica_type, idx, status} <- [
            {:primary, 0, {:ready, _idle = 3, 0, _checked_out = 1}},
            {:replica, 1, {:ready, _idle = 1, 0, _checked_out = 2}}
          ] do
        start_supervised!(
          {FakePool, {{:pool, replica_type, idx, id}, status}},
          id: :"fake_pool_#{idx}"
        )
      end

      ref = attach_handler([:supavisor, :pool, :connections])
      Tenant.execute_pool_metrics()

      # idle: 3+1=4, checked_out: 1+2=3, exactly ONE event (not two)
      assert_receive {^ref, {[:supavisor, :pool, :connections], %{idle: 4, checked_out: 3}, meta}}
      assert meta.tenant == "pool_cluster_test"
      refute_receive {^ref, {[:supavisor, :pool, :connections], %{idle: 3, checked_out: 1}, _}}
      refute_receive {^ref, {[:supavisor, :pool, :connections], %{idle: 1, checked_out: 2}, _}}
    end
  end

  def handle_event(event_name, measurement, meta, {pid, ref}) do
    send(pid, {ref, {event_name, measurement, meta}})
  end

  defp attach_handler(event) do
    ref = make_ref()

    :telemetry.attach(
      {ref, :test},
      event,
      &__MODULE__.handle_event/4,
      {self(), ref}
    )

    on_exit(fn ->
      :telemetry.detach({ref, :test})
    end)

    ref
  end

  defmodule FakePool do
    @moduledoc false
    use GenServer

    def start_link({registry_key, status}),
      do: GenServer.start_link(__MODULE__, {registry_key, status})

    @impl true
    def init({registry_key, status}) do
      Registry.register(Supavisor.Registry.Tenants, registry_key, :primary)
      {:ok, status}
    end

    @impl true
    def handle_call(:status, _from, status), do: {:reply, status, status}
  end
end
