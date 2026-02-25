defmodule MetricsBench do
  @moduledoc """
  Benchmark for Supavisor metrics collection at scale.

  Simulates 5,000 tenants with realistic metric data, then measures
  the time to scrape metrics.

  ## Key Features:
  - 80% of tenants have 1 user, 10% have 2 users, 10% have 3 users
  - All tenants use the same database (realistic for multi-tenant setup)
  - Concurrent event emission across all schedulers (important for Peep's
    striped storage - one ETS table per scheduler)
  - Emits hundreds of events per tenant/user with varied counts to simulate
    realistic production load
  - Tests all metric types: counters, sums, distributions, last_values
  - NO database interaction - pure in-memory metrics only
  """

  alias Supavisor.Monitoring.PromEx

  @num_tenants 5_000

  def setup do
    IO.puts("\n=== Setting up metrics benchmark ===")
    IO.puts("Generating #{@num_tenants} tenant configurations...")

    # Start the application if not already started
    Application.ensure_all_started(:supavisor)

    # Set log level to error to reduce noise
    Logger.configure(level: :error)

    # Generate tenant/user combinations
    tenant_users = generate_tenant_users()

    IO.puts("✓ Generated #{length(tenant_users)} tenant/user combinations")
    IO.puts("\nPopulating metrics data...")

    # Populate metrics concurrently
    populate_metrics(tenant_users)

    IO.puts("✓ Metrics populated")
    IO.puts("\nSetup complete!\n")

    :ok
  end

  defp generate_tenant_users do
    for i <- 1..@num_tenants do
      tenant_id = "bench_tenant_#{String.pad_leading(Integer.to_string(i), 4, "0")}"
      num_users = user_count_for_tenant(i)

      users =
        for j <- 1..num_users do
          mode = if j == 1 or rem(j, 2) == 0, do: :transaction, else: :session
          user_name = if num_users == 1, do: "postgres", else: "user_#{j}"

          %{
            tenant_id: tenant_id,
            user: user_name,
            mode: mode,
            db_name: "postgres",
            search_path: "public"
          }
        end

      users
    end
    |> List.flatten()
  end

  defp user_count_for_tenant(i) do
    # 80% have 1 user, 10% have 2 users, 10% have 3 users
    cond do
      rem(i, 10) < 8 -> 1
      rem(i, 10) < 9 -> 2
      true -> 3
    end
  end

  defp populate_metrics(tenant_users) do
    # Register fake clients in registries
    IO.puts("  Registering clients in registries...")
    register_fake_clients(tenant_users)

    # Emit telemetry events concurrently across schedulers
    IO.puts("  Emitting telemetry events concurrently...")
    emit_telemetry_events(tenant_users)

    # Trigger polling metrics
    IO.puts("  Triggering polling metrics...")
    trigger_polling_metrics()
  end

  defp register_fake_clients(tenant_users) do
    # Register fake client PIDs in the registries
    Enum.each(tenant_users, fn config ->
      id = {
        {:single, config.tenant_id},
        config.user,
        config.mode,
        config.db_name,
        config.search_path
      }

      # Register 5-20 fake clients per tenant/user
      num_clients = Enum.random(5..20)

      for _ <- 1..num_clients do
        started_at = System.monotonic_time() - Enum.random(1_000..3_600_000_000)

        Registry.register(
          Supavisor.Registry.TenantClients,
          id,
          started_at: started_at
        )
      end

      # Register 2-10 fake proxy clients
      num_proxy = Enum.random(2..10)

      for _ <- 1..num_proxy do
        started_at = System.monotonic_time() - Enum.random(1_000..3_600_000_000)

        Registry.register(
          Supavisor.Registry.TenantProxyClients,
          id,
          started_at: started_at
        )
      end

      # Register tenant supervisor
      Registry.register(
        Supavisor.Registry.TenantSups,
        config.tenant_id,
        []
      )
    end)
  end

  defp emit_telemetry_events(tenant_users) do
    # Emit telemetry events concurrently to distribute across schedulers
    # This is important because Peep storage is striped per scheduler
    num_schedulers = :erlang.system_info(:schedulers_online)
    IO.puts("    Spawning concurrent tasks across #{num_schedulers} schedulers...")

    tenant_users
    |> Task.async_stream(
      fn config ->
        emit_events_for_tenant_user(config)
      end,
      max_concurrency: num_schedulers * 2,
      timeout: :infinity
    )
    |> Stream.run()
  end

  defp emit_events_for_tenant_user(config) do
    tags = %{
      tenant: config.tenant_id,
      user: config.user,
      mode: config.mode,
      type: :single,
      db_name: config.db_name,
      search_path: config.search_path
    }

    # Emit many events per tenant/user to stress the system
    num_queries = Enum.random(100..1000)
    num_checkouts = Enum.random(50..500)
    num_connections = Enum.random(10..50)
    num_network_stats = Enum.random(20..100)

    # Pool checkout events (local and remote)
    for _ <- 1..num_checkouts do
      :telemetry.execute(
        [:supavisor, :pool, :checkout, :stop, :local],
        %{duration: Enum.random(1_000..500_000)},
        tags
      )

      # Some remote checkouts too
      if rem(Enum.random(1..100), 3) == 0 do
        :telemetry.execute(
          [:supavisor, :pool, :checkout, :stop, :remote],
          %{duration: Enum.random(5_000..2_000_000)},
          tags
        )
      end
    end

    # Query events
    for _ <- 1..num_queries do
      :telemetry.execute(
        [:supavisor, :client, :query, :stop],
        %{duration: Enum.random(1_000_000..1_000_000_000)},
        Map.put(tags, :proxy, false)
      )

      # Some proxy queries
      if rem(Enum.random(1..100), 5) == 0 do
        :telemetry.execute(
          [:supavisor, :client, :query, :stop],
          %{duration: Enum.random(1_000_000..500_000_000)},
          Map.put(tags, :proxy, true)
        )
      end
    end

    # Network events
    for _ <- 1..num_network_stats do
      :telemetry.execute(
        [:supavisor, :client, :network, :stat],
        %{
          recv_oct: Enum.random(1_000..10_000_000),
          send_oct: Enum.random(1_000..10_000_000)
        },
        tags
      )

      :telemetry.execute(
        [:supavisor, :db, :network, :stat],
        %{
          recv_oct: Enum.random(1_000..10_000_000),
          send_oct: Enum.random(1_000..10_000_000)
        },
        tags
      )
    end

    # Connection events
    for _ <- 1..num_connections do
      :telemetry.execute(
        [:supavisor, :client, :connection, :stop],
        %{duration: Enum.random(1_000_000..100_000_000)},
        tags
      )
    end

    # Handler lifecycle events (multiple per tenant/user)
    handler_events = Enum.random(5..20)

    for _ <- 1..handler_events do
      :telemetry.execute([:supavisor, :client_handler, :started, :all], %{}, tags)
      :telemetry.execute([:supavisor, :client_handler, :stopped, :all], %{}, tags)
      :telemetry.execute([:supavisor, :db_handler, :started, :all], %{}, tags)
      :telemetry.execute([:supavisor, :db_handler, :stopped, :all], %{}, tags)
    end

    # Handler state transitions
    state_transitions = Enum.random(10..50)

    for _ <- 1..state_transitions do
      from_state = Enum.random([:init, :auth, :ready, :busy, :idle])
      to_state = Enum.random([:auth, :ready, :busy, :idle, :closing])

      :telemetry.execute(
        [:supavisor, :client_handler, :state],
        %{duration: Enum.random(1_000..100_000_000)},
        %{tenant: config.tenant_id, from_state: from_state, to_state: to_state}
      )
    end

    # Client joins
    join_events = Enum.random(5..50)

    for _ <- 1..join_events do
      :telemetry.execute([:supavisor, :client, :joins, :ok], %{}, tags)

      # Some failures too
      if rem(Enum.random(1..100), 10) == 0 do
        :telemetry.execute([:supavisor, :client, :joins, :fail], %{}, tags)
      end
    end

    # Database handler events
    db_events = Enum.random(5..30)

    for _ <- 1..db_events do
      :telemetry.execute([:supavisor, :db_handler, :db_connection, :all], %{}, tags)

      # Some prepared statement evictions
      if rem(Enum.random(1..100), 20) == 0 do
        :telemetry.execute(
          [:supavisor, :db_handler, :prepared_statements, :evicted],
          %{},
          tags
        )
      end
    end

    :ok
  end

  defp trigger_polling_metrics do
    # Manually trigger the polling metrics to populate last_value gauges
    Supavisor.PromEx.Plugins.Tenant.execute_tenant_metrics()
    Supavisor.PromEx.Plugins.Tenant.execute_tenant_proxy_metrics()
    Supavisor.PromEx.Plugins.Tenant.execute_conn_tenants_metrics()
    Supavisor.PromEx.Plugins.Tenant.execute_client_connections_lifetime()
  end

  def print_stats do
    IO.puts("\n=== Benchmark Statistics ===")

    num_schedulers = :erlang.system_info(:schedulers_online)
    IO.puts("System schedulers: #{num_schedulers}")

    # Count registrations
    num_clients =
      Registry.select(Supavisor.Registry.TenantClients, [{{:_, :_, :_}, [], [true]}])
      |> length()

    num_proxy =
      Registry.select(Supavisor.Registry.TenantProxyClients, [{{:_, :_, :_}, [], [true]}])
      |> length()

    num_tenant_sups =
      Registry.select(Supavisor.Registry.TenantSups, [{{:_, :_, :_}, [], [true]}])
      |> length()

    IO.puts("Total client registrations: #{num_clients}")
    IO.puts("Total proxy client registrations: #{num_proxy}")
    IO.puts("Total tenant supervisors: #{num_tenant_sups}")

    # Fetch metrics and measure size
    IO.puts("\nFetching metrics to measure output size...")
    metrics = PromEx.get_metrics() |> IO.iodata_to_binary()
    size_mb = byte_size(metrics) / 1_024 / 1_024

    IO.puts("Metrics output size: #{Float.round(size_mb, 2)} MB")
    IO.puts("Metrics output lines: #{String.split(metrics, "\n") |> length()}")

    # Count unique metric series
    metric_lines =
      metrics
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "#"))
      |> Enum.reject(&(&1 == ""))

    IO.puts("Metric series count: #{length(metric_lines)}")

    IO.puts("\n")
  end
end

# Run the benchmark
IO.puts("╔═══════════════════════════════════════════════════════════════╗")
IO.puts("║         Supavisor Metrics Benchmark (5,000 Tenants)          ║")
IO.puts("╚═══════════════════════════════════════════════════════════════╝")

MetricsBench.setup()
MetricsBench.print_stats()

IO.puts("=== Running Benchmark ===\n")

Benchee.run(
  %{
    "fetch_metrics (local node)" => fn ->
      Supavisor.Monitoring.PromEx.get_metrics()
    end
  },
  time: 10,
  memory_time: 5,
  warmup: 2,
  formatters: [
    {Benchee.Formatters.Console, comparison: false, extended_statistics: true}
  ]
)

IO.puts("\n✓ Benchmark complete!")
