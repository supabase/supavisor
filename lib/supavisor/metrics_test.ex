defmodule Supavisor.MetricsTest do
  @moduledoc """
  Temporary module for testing Prometheus export implementations.
  Compares Elixir vs Rust NIF outputs.
  """

  alias Supavisor.Monitoring.PromEx

  @doc """
  Generates some test metrics with edge cases and regular data.
  """
  def generate_test_metrics(num_tenants \\ 1000, queries_per_tenant \\ 10) do
    IO.puts("Generating test metrics with edge cases...")

    # Test various escaping scenarios
    edge_cases = [
      # Quotes in values
      %{tenant: "tenant_with_\"quotes\"", user: "user\"with\"quotes", db_name: "test_db"},
      # Backslashes
      %{tenant: "tenant\\with\\backslash", user: "user\\backslash", db_name: "test_db"},
      # Newlines
      %{tenant: "tenant\nwith\nnewline", user: "user\nnewline", db_name: "test_db"},
      # Mixed special chars
      %{tenant: "tenant_\"with\"\nmixed\\chars", user: "user_mixed", db_name: "test_db"},
      # Very long strings
      %{tenant: String.duplicate("long_tenant_name_", 10), user: "long_user", db_name: "test_db"},
      # Unicode characters
      %{tenant: "tenant_with_émojis_🚀", user: "user_unicode_日本語", db_name: "test_db"},
      # Empty-ish values
      %{tenant: "", user: "empty_tenant", db_name: "test_db"},
      # Numeric-looking strings
      %{tenant: "12345", user: "67890", db_name: "test_db"}
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

    IO.puts(
      "Generating #{num_tenants} tenants with #{queries_per_tenant} queries each (in parallel)..."
    )

    # Generate all entries first, interleaving tenants
    entries =
      for tenant_id <- 1..num_tenants,
          query_num <- 1..queries_per_tenant do
        tenant = "tenant_#{tenant_id}"
        type = :write
        mode = Enum.random([:transaction, :session])
        db_name = "postgres"
        user = "postgres.#{tenant}"
        search_path = "public"
        proxy = Enum.random([true, false])
        duration = System.convert_time_unit(Enum.random(1..100), :millisecond, :native)

        {tenant_id, query_num, tenant, user, mode, type, db_name, search_path, proxy, duration}
      end

    # Now execute them in parallel - this spreads tenants across different threads/tables
    entries
    |> Task.async_stream(
      fn {tenant_id, query_num, tenant, user, mode, type, db_name, search_path, proxy, duration} ->
        :telemetry.execute(
          [:supavisor, :client, :query, :stop],
          %{duration: duration},
          %{
            tenant: tenant,
            user: user,
            mode: mode,
            type: type,
            db_name: db_name,
            search_path: search_path,
            proxy: proxy
          }
        )

        # Print progress every 5000 entries
        total_entry = (tenant_id - 1) * queries_per_tenant + query_num

        if rem(total_entry, 5000) == 0 do
          IO.puts("  Processed #{total_entry} entries...")
        end

        :ok
      end,
      max_concurrency: System.schedulers_online() * 2,
      timeout: :infinity
    )
    |> Stream.run()

    IO.puts("Test metrics generated!")
  end

  @doc """
  Compares Elixir and Rust Prometheus export outputs.
  Returns :ok if they match, or {:error, differences} if they don't.
  """
  def compare_outputs do
    IO.puts("Comparing Elixir vs Rust outputs...")

    elixir_output = PromEx.get_metrics() |> IO.iodata_to_binary()
    rust_output = PromEx.get_metrics_rustler() |> IO.iodata_to_binary()

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

    elixir_lines = String.split(elixir_output, "\n") |> Enum.map(normalize_floats)
    rust_lines = String.split(rust_output, "\n") |> Enum.map(normalize_floats)

    if elixir_lines == rust_lines do
      IO.puts("✓ Outputs match (ignoring float formatting differences)!\n")
      :ok
    else
      IO.puts("✗ OUTPUTS DIFFER!")

      # Show size difference
      IO.puts("Elixir output size: #{byte_size(elixir_output)} bytes")
      IO.puts("Rust output size: #{byte_size(rust_output)} bytes")

      IO.puts("\nElixir output has #{length(elixir_lines)} lines")
      IO.puts("Rust output has #{length(rust_lines)} lines")

      # Compare line by line
      differences =
        Enum.zip(elixir_lines, rust_lines)
        |> Enum.with_index()
        |> Enum.filter(fn {{line1, line2}, _idx} -> line1 != line2 end)
        |> Enum.take(10)

      # Show first 10 differences
      if differences != [] do
        IO.puts("\nFirst differences:")

        for {{elixir_line, rust_line}, idx} <- differences do
          IO.puts("\nLine #{idx + 1}:")
          IO.puts("  Elixir: #{inspect(elixir_line)}")
          IO.puts("  Rust:   #{inspect(rust_line)}")
        end
      end

      # Check if one output is longer
      if length(elixir_lines) > length(rust_lines) do
        IO.puts("\nExtra lines in Elixir output (showing first 5):")

        Enum.drop(elixir_lines, length(rust_lines))
        |> Enum.take(5)
        |> Enum.each(&IO.puts("  #{inspect(&1)}"))
      else
        if length(rust_lines) > length(elixir_lines) do
          IO.puts("\nExtra lines in Rust output (showing first 5):")

          Enum.drop(rust_lines, length(elixir_lines))
          |> Enum.take(5)
          |> Enum.each(&IO.puts("  #{inspect(&1)}"))
        end
      end

      IO.puts("\n")
      {:error, :outputs_differ}
    end
  end

  @doc """
  Run full test: generate metrics and compare outputs.
  """
  def run_test do
    generate_test_metrics()
    Process.sleep(100)
    compare_outputs()
  end

  @doc """
  Starts a background process that calls get_metrics_rustler/0 every 15 seconds.
  Returns the PID of the background process.

  ## Examples

      iex> pid = Supavisor.MetricsTest.start_background_polling()
      iex> Process.alive?(pid)
      true
      iex> Supavisor.MetricsTest.stop_background_polling(pid)
      :ok
  """
  def start_background_polling do
    spawn_link(fn -> poll_loop() end)
  end

  @doc """
  Stops a background polling process.
  """
  def stop_background_polling(pid) when is_pid(pid) do
    Process.exit(pid, :normal)
    :ok
  end

  defp poll_loop do
    IO.puts("[#{DateTime.utc_now()}] Calling get_metrics_rustler()...")
    start_time = System.monotonic_time(:millisecond)

    try do
      result = PromEx.get_metrics_rustler()
      elapsed = System.monotonic_time(:millisecond) - start_time
      size = IO.iodata_length(result)
      IO.puts("  ✓ Completed in #{elapsed}ms, output size: #{size} bytes")
    rescue
      e ->
        elapsed = System.monotonic_time(:millisecond) - start_time
        IO.puts("  ✗ Error after #{elapsed}ms: #{inspect(e)}")
    end

    IO.puts("[#{DateTime.utc_now()}] Calling get_metrics_peepers2()...")
    start_time = System.monotonic_time(:millisecond)

    try do
      result = PromEx.get_metrics_peepers2()
      elapsed = System.monotonic_time(:millisecond) - start_time
      size = IO.iodata_length(result)
      IO.puts("  ✓ Completed in #{elapsed}ms, output size: #{size} bytes")
    rescue
      e ->
        elapsed = System.monotonic_time(:millisecond) - start_time
        IO.puts("  ✗ Error after #{elapsed}ms: #{inspect(e)}")
    end

    Process.sleep(15_000)
    poll_loop()
  end
end
