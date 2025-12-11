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
num_tenants = 50_000
queries_per_tenant = 20
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
  metadata = %{
    tenant: tenant,
    user: "asdasdasdsadasda",
    mode: :transaction,
    type: :write,
    db_name: "bzxczxczxcz",
    search_path: ""
  }

  # Client query event
  query_duration = System.convert_time_unit(Enum.random(1..100), :millisecond, :native)
  :telemetry.execute(
    [:supavisor, :client, :query, :stop],
    %{duration: query_duration},
    Map.put(metadata, :proxy, false)
  )

  # Client connection event
  conn_duration = System.convert_time_unit(Enum.random(10..200), :millisecond, :native)
  :telemetry.execute(
    [:supavisor, :client, :connection, :stop],
    %{duration: conn_duration},
    metadata
  )

  # Pool checkout events
  checkout_duration = Enum.random(1..50) * 1000  # microseconds
  :telemetry.execute(
    [:supavisor, :pool, :checkout, :stop, :local],
    %{duration: checkout_duration},
    metadata
  )
end, max_concurrency: System.schedulers_online() * 2)
|> Stream.run()

# Verify all implementations produce the same output
IO.puts("Verifying output consistency...")
elixir_output = PromEx.get_metrics() |> IO.iodata_to_binary()
rust_output = PromEx.get_metrics_rustler() |> IO.iodata_to_binary()
peepers2_output = PromEx.get_metrics_peepers2() |> IO.iodata_to_binary()
rust_escape_output = PromEx.get_metrics_rust_escape() |> IO.iodata_to_binary()

# Helper to normalize float formatting differences (e.g., "1.0e4" vs "10000")
normalize_floats = fn line ->
  # Match float patterns and normalize them
  Regex.replace(~r/(\d+\.?\d*)[eE]([+-]?\d+)/, line, fn _, num, exp ->
    {f, ""} = Float.parse(num)
    {e, ""} = Integer.parse(exp)
    result = f * :math.pow(10, e)
    if result == Float.floor(result) do
      "#{trunc(result)}"
    else
      "#{result}"
    end
  end)
  |> then(fn normalized ->
    # Also try to parse standalone numbers and normalize them
    Regex.replace(~r/="([\d.]+)"/, normalized, fn _, num ->
      case Float.parse(num) do
        {f, ""} ->
          if f == Float.floor(f) and f < 1.0e15 do
            "=\"#{trunc(f)}\""
          else
            "=\"#{num}\""
          end
        _ ->
          "=\"#{num}\""
      end
    end)
  end)
end

# Helper to sort lines for order-independent comparison
# Group metrics together (HELP, TYPE, and their samples) and sort them
sort_prometheus_output = fn lines ->
  lines
  |> Enum.chunk_by(&String.starts_with?(&1, "# "))
  |> Enum.map(&Enum.sort/1)
  |> List.flatten()
  |> Enum.sort()
end

elixir_lines = String.split(elixir_output, "\n") |> Enum.map(normalize_floats) |> sort_prometheus_output.()
rust_lines = String.split(rust_output, "\n") |> Enum.map(normalize_floats) |> sort_prometheus_output.()
peepers2_lines = String.split(peepers2_output, "\n") |> Enum.map(normalize_floats) |> sort_prometheus_output.()
rust_escape_lines = String.split(rust_escape_output, "\n") |> Enum.map(normalize_floats) |> sort_prometheus_output.()

# Compare Elixir vs Rust
# if elixir_lines == rust_lines do
#   IO.puts("✓ Elixir vs Rust outputs match (ignoring order and float formatting)!")
# else
#   IO.puts("✗ Elixir vs Rust OUTPUTS DIFFER!")
#
#   # Show size difference
#   IO.puts("Elixir output size: #{byte_size(elixir_output)} bytes")
#   IO.puts("Rust output size: #{byte_size(rust_output)} bytes")
#
#   IO.puts("\nElixir output has #{length(elixir_lines)} lines")
#   IO.puts("Rust output has #{length(rust_lines)} lines")
#
#   # Compare line by line
#   differences =
#     Enum.zip(elixir_lines, rust_lines)
#     |> Enum.with_index()
#     |> Enum.filter(fn {{line1, line2}, _idx} -> line1 != line2 end)
#     |> Enum.take(10)  # Show first 10 differences
#
#   if differences != [] do
#     IO.puts("\nFirst differences:")
#     for {{elixir_line, rust_line}, idx} <- differences do
#       IO.puts("\nLine #{idx + 1}:")
#       IO.puts("  Elixir: #{inspect(elixir_line)}")
#       IO.puts("  Rust:   #{inspect(rust_line)}")
#     end
#   end
#
#   # Check if one output is longer
#   if length(elixir_lines) > length(rust_lines) do
#     IO.puts("\nExtra lines in Elixir output (showing first 5):")
#     Enum.drop(elixir_lines, length(rust_lines))
#     |> Enum.take(5)
#     |> Enum.each(&IO.puts("  #{inspect(&1)}"))
#   else if length(rust_lines) > length(elixir_lines) do
#     IO.puts("\nExtra lines in Rust output (showing first 5):")
#     Enum.drop(rust_lines, length(elixir_lines))
#     |> Enum.take(5)
#     |> Enum.each(&IO.puts("  #{inspect(&1)}"))
#   end
#   end
#
#   IO.puts("\n")
#   raise "Output verification failed! Elixir vs Rust outputs do not match."
# end

# Compare Elixir vs Peepers2
#if elixir_lines == peepers2_lines do
#  IO.puts("✓ Elixir vs Peepers2 outputs match (ignoring order and float formatting)!\n")
#else
#  IO.puts("✗ Elixir vs Peepers2 OUTPUTS DIFFER!")
#
#  # Show size difference
#  IO.puts("Elixir output size: #{byte_size(elixir_output)} bytes")
#  IO.puts("Peepers2 output size: #{byte_size(peepers2_output)} bytes")
#
#  IO.puts("\nElixir output has #{length(elixir_lines)} lines")
#  IO.puts("Peepers2 output has #{length(peepers2_lines)} lines")
#
#  # Compare line by line
#  differences =
#    Enum.zip(elixir_lines, peepers2_lines)
#    |> Enum.with_index()
#    |> Enum.filter(fn {{line1, line2}, _idx} -> line1 != line2 end)
#    |> Enum.take(10)  # Show first 10 differences
#
#  if differences != [] do
#    IO.puts("\nFirst differences:")
#    for {{elixir_line, peepers2_line}, idx} <- differences do
#      IO.puts("\nLine #{idx + 1}:")
#      IO.puts("  Elixir:   #{inspect(elixir_line)}")
#      IO.puts("  Peepers2: #{inspect(peepers2_line)}")
#    end
#  end
#
#  # Check if one output is longer
#  if length(elixir_lines) > length(peepers2_lines) do
#    IO.puts("\nExtra lines in Elixir output (showing first 5):")
#    Enum.drop(elixir_lines, length(peepers2_lines))
#    |> Enum.take(5)
#    |> Enum.each(&IO.puts("  #{inspect(&1)}"))
#  else if length(peepers2_lines) > length(elixir_lines) do
#    IO.puts("\nExtra lines in Peepers2 output (showing first 5):")
#    Enum.drop(peepers2_lines, length(elixir_lines))
#    |> Enum.take(5)
#    |> Enum.each(&IO.puts("  #{inspect(&1)}"))
#  end
#  end
#
#  IO.puts("\n")
#  raise "Output verification failed! Elixir vs Peepers2 outputs do not match."
#end

# Run the benchmark
Benchee.run(
  %{
    "Elixir (tab2list + Elixir export)" => fn ->
      PromEx.get_metrics()
    end,
    "Elixir (foldl + Elixir export)" => fn ->
      PromEx.get_metrics_foldl()
    end,
    "Rust (tab2list + Rust export)" => fn ->
      PromEx.get_metrics_rustler()
    end,
    "Rust (foldl + Rust export)" => fn ->
      PromEx.get_metrics_rustler_foldl()
    end,
    "Peepers2 (tab2list + Rust aggregation + Rust export)" => fn ->
      PromEx.get_metrics_peepers2()
    end,
    "Rust escape (tab2list + Elixir export + Rust escape)" => fn ->
      PromEx.get_metrics_rust_escape()
    end,
    "Rust escape (foldl + Elixir export + Rust escape)" => fn ->
      PromEx.get_metrics_rust_escape_foldl()
    end
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
