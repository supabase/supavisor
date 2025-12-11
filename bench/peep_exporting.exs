# Benchmark for Supavisor.Monitoring.PromEx.get_metrics/0
#
# This benchmark measures the performance of get_metrics/0 when aggregating
# metrics from a large number of tenants (20,000+). This helps identify
# performance bottlenecks in metric collection and aggregation.
#
# Usage:
#   mix run bench/get_metrics.exs

alias Supavisor.Monitoring.PromEx

# Configuration
num_tenants = 25_000
queries_per_tenant = 10
Logger.configure(level: :error)

# Start the application to initialize PromEx and its dependencies
{:ok, _} = Application.ensure_all_started(:supavisor)

# Give PromEx time to fully initialize
Process.sleep(1_000)

# Setup function to populate metrics with realistic tenant data
IO.puts("Setting up #{num_tenants} tenants with #{queries_per_tenant} queries each...")
start_time = System.monotonic_time(:millisecond)

# First, add some edge case metrics to test escaping and special characters
IO.puts("Adding edge case metrics for testing escaping...")

# Test various escaping scenarios
edge_cases = [
  %{tenant: "tenant_with_\"quotes\"", user: "user\"with\"quotes", db_name: "test_db"},
  %{tenant: "tenant\\with\\backslash", user: "user\\backslash", db_name: "test_db"},
  %{tenant: "tenant\nwith\nnewline", user: "user\nnewline", db_name: "test_db"},
  %{tenant: "tenant_\"with\"\nmixed\\chars", user: "user_mixed", db_name: "test_db"},
  %{tenant: String.duplicate("long_tenant_name_", 10), user: "long_user", db_name: "test_db"},
  %{tenant: "tenant_with_émojis_🚀", user: "user_unicode_日本語", db_name: "test_db"},
  %{tenant: "", user: "empty_tenant", db_name: "test_db"},
  %{tenant: "12345", user: "67890", db_name: "test_db"},
]

for edge_case <- edge_cases do
  :telemetry.execute(
    [:supavisor, :client, :query, :stop],
    %{duration: 1000},
    Map.merge(edge_case, %{
      mode: :session,
      type: :write,
      search_path: "public",
      proxy: false
    })
  )
end

# Generate metrics for different tenants
for tenant_id <- 1..num_tenants, _ <- 1..queries_per_tenant do
  "tenant_#{tenant_id}"
end
|> Task.async_stream(fn tenant ->
  # Simulate query durations between 1ms and 100ms (in native time)
  duration = System.convert_time_unit(Enum.random(1..100), :millisecond, :native)

  :telemetry.execute(
    [:supavisor, :client, :query, :stop],
    %{duration: duration},
    %{
      tenant: tenant,
      user: "asdasdasdsadasda",
      mode: :transaction,
      type: :write,
      db_name: "bzxczxczxcz",
      search_path: "",
      proxy: false
    }
  )
end)
|> Stream.run()

metrics =  PromEx.fetch_metrics()
# Run the benchmark
Benchee.run(
  %{
    "default exporter" => fn ->
      Peep.Prometheus.export(metrics)
    end,
    "iodata escaping" => fn ->
      Supavisor.PeepEscapeIodata.export(metrics)
    end,
    "binary replace escaping" => fn ->
      Supavisor.PeepEscapeBinaryReplace.export(metrics)
    end,
  },
  warmup: 2,
  time: 10,
  memory_time: 2,
  formatters: [
    Benchee.Formatters.Console
  ],
  #profile_after: :fprof,
  print: [
    benchmarking: true,
    fast_warning: false,
    configuration: true
  ]
)
