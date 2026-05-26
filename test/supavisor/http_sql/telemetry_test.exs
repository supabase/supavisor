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

    test "emits start and stop for an :ok Neon-shape body (rowCount → response_rows)" do
      meta = %{tenant: "t1", user: "u", mode: :single, batch_size: "1"}

      neon_body = %{"command" => "SELECT", "rowCount" => 3, "rows" => [["1"], ["2"], ["3"]]}

      assert {:ok, ^neon_body} = Telemetry.request_span(meta, fn -> {:ok, neon_body} end)

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :start], _, %{tenant: "t1"}}

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :stop], %{duration: _},
                       %{status_code: 200, response_rows: 3}}
    end

    test "batch body sums rowCount across results" do
      meta = %{tenant: "t1", user: "u", mode: :batch, batch_size: "2-10"}

      batch_body = %{"results" => [%{"rowCount" => 1}, %{"rowCount" => 4}, %{"rowCount" => 2}]}

      assert {:ok, _} = Telemetry.request_span(meta, fn -> {:ok, batch_body} end)

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :stop], _,
                       %{status_code: 200, response_rows: 7}}
    end

    test "emits stop with status 500 for an :error body" do
      meta = %{tenant: "t1", user: "u", mode: :single, batch_size: 1}

      assert {:error, :nope} = Telemetry.request_span(meta, fn -> {:error, :nope} end)

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :stop], _,
                       %{status_code: 500}}
    end

    test "emits stop with status 429 for MaxConnectionsError" do
      meta = %{tenant: "t1", user: "u", mode: :single, batch_size: 1}

      err = %Supavisor.Errors.MaxConnectionsError{}

      assert {:error, ^err} = Telemetry.request_span(meta, fn -> {:error, err} end)

      assert_received {:telemetry, [:supavisor, :http_sql, :request, :stop], _,
                       %{status_code: 429}}
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

      assert_received {:telemetry, %{duration: 123}, %{hit?: :hit, tenant: "t", user: "u"}}
    end

    test "tags miss?" do
      Telemetry.pool_checkout(999, :miss, %{tenant: "t", user: "u"})
      assert_received {:telemetry, %{duration: 999}, %{hit?: :miss}}
    end
  end

  describe "max_clients_rejected/2" do
    setup do
      handler_id = make_ref()

      :telemetry.attach(
        handler_id,
        [:supavisor, :http_sql, :max_clients_rejected],
        fn _name, m, md, owner -> send(owner, {:telemetry, m, md}) end,
        self()
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)
      :ok
    end

    test "emits a counter with the limit_kind tag" do
      Telemetry.max_clients_rejected(%{tenant: "t", user: "u"})

      assert_received {:telemetry, %{count: 1},
                       %{tenant: "t", user: "u", limit_kind: :max_clients}}
    end
  end
end
