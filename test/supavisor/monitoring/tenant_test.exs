defmodule Supavisor.PromEx.Plugins.TenantTest do
  use Supavisor.E2ECase, async: false

  alias Supavisor.PromEx.Plugins.Tenant

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
end
