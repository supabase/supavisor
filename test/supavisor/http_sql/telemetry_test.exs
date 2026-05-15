defmodule Supavisor.HttpSql.TelemetryTest do
  use ExUnit.Case, async: false

  alias Supavisor.HttpSql.Telemetry

  describe "request_span/2" do
    setup do
      handler_id = make_ref()

      :telemetry.attach_many(
        handler_id,
        [
          [:supavisor, :http_sql, :request, :start],
          [:supavisor, :http_sql, :request, :stop],
          [:supavisor, :http_sql, :request, :exception]
        ],
        fn name, measurements, metadata, owner ->
          send(owner, {:telemetry, name, measurements, metadata})
        end,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)
      :ok
    end

    test "emits start and stop for an :ok body" do
      meta = %{tenant: "t1", user: "u", mode: :single, batch_size: 1}

      assert {:ok, %{rows: [["1"]], rows_count: 1, bytes: 42}} =
               Telemetry.request_span(meta, fn ->
                 {:ok, %{rows: [["1"]], rows_count: 1, bytes: 42}}
               end)

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :start], _, %{tenant: "t1"}}

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :stop], %{duration: _},
                       %{status_code: 200, response_rows: 1, response_bytes: 42}}
    end

    test "emits stop with status 500 for an :error body" do
      meta = %{tenant: "t1", user: "u", mode: :single, batch_size: 1}

      assert {:error, :nope} = Telemetry.request_span(meta, fn -> {:error, :nope} end)

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :stop], _,
                       %{status_code: 500}}
    end

    test "emits exception when the body raises" do
      meta = %{tenant: "t1", user: "u", mode: :single, batch_size: 1}

      assert_raise RuntimeError, "boom", fn ->
        Telemetry.request_span(meta, fn -> raise "boom" end)
      end

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :exception], _, _}
    end
  end

  describe "pool_checkout/3" do
    setup do
      handler_id = make_ref()

      :telemetry.attach(
        handler_id,
        [:supavisor, :http_sql, :pool, :checkout],
        fn _name, m, md, owner -> send(owner, {:telemetry, m, md}) end,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)
      :ok
    end

    test "tags hit?" do
      Telemetry.pool_checkout(123, :hit, %{tenant: "t", user: "u"})

      assert_received {:telemetry, %{duration: 123},
                       %{hit?: :hit, tenant: "t", user: "u"}}
    end

    test "tags miss?" do
      Telemetry.pool_checkout(999, :miss, %{tenant: "t", user: "u"})
      assert_received {:telemetry, %{duration: 999}, %{hit?: :miss}}
    end
  end
end
