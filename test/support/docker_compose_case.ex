defmodule Supavisor.DockerComposeCase do
  @moduledoc """
  Sets up and manages lifecycle of various Docker containers
  required by an integration test.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      import Supavisor.DockerComposeCase
    end
  end

  setup_all do
    # Generate certificates if they don't exist
    ensure_certificates()

    # Start docker compose services
    start_docker_compose()

    # Wait for services to be healthy
    wait_for_services()

    on_exit(fn ->
      nil
      stop_docker_compose()
      cleanup_certificates()
    end)

    :ok
  end

  defp ensure_certificates do
    cert_dir = Path.expand("../integration/jit-access/postgres/certs", __DIR__)
    ca_cert = Path.join(cert_dir, "ca.crt")

    unless File.exists?(ca_cert) do
      IO.puts("Generating test certificates...")

      {output, exit_code} =
        System.cmd("#{cert_dir}/generate_test_certs.sh", [cert_dir])

      if exit_code != 0 do
        raise "Failed to generate certificates: #{output}"
      end

      IO.puts("✓ Certificates generated")
    end
  end

  defp cleanup_certificates do
    cert_dir = Path.expand("../integration/jit-access/postgres/certs", __DIR__)
    IO.puts("Removing test certificates from #{cert_dir}/...")

    if File.dir?(cert_dir) do
      [
        cert_dir <> "/*.key",
        cert_dir <> "/*.crt",
        cert_dir <> "/*.csr",
        cert_dir <> "/*.srl",
        cert_dir <> "/*.ext"
      ]
      |> Enum.flat_map(&Path.wildcard/1)
      |> Enum.each(&File.rm!/1)

      IO.puts("✓ Certificates removed successfully")
    else
      IO.puts("No certificates directory found at #{cert_dir}")
    end
  end

  def start_docker_compose do
    IO.puts("Starting Docker Compose services...")

    {output, exit_code} =
      System.cmd("docker-compose", ["up", "-d"],
        stderr_to_stdout: true,
        cd: Path.expand("../integration/jit-access", __DIR__)
      )

    if exit_code != 0 do
      raise "Failed to start Docker Compose: #{output}"
    end

    IO.puts("Docker Compose services started")
  end

  def stop_docker_compose do
    IO.puts("Stopping Docker Compose services...")

    System.cmd("docker-compose", ["down", "-v"],
      stderr_to_stdout: true,
      cd: Path.expand("../integration/jit-access", __DIR__)
    )

    IO.puts("Docker Compose services stopped")
  end

  def wait_for_services(max_attempts \\ 30, delay_ms \\ 1000) do
    IO.puts("Waiting for services to be ready...")

    Enum.reduce_while(1..max_attempts, nil, fn attempt, _acc ->
      case check_service_health() do
        :ok ->
          IO.puts("All services are ready!")
          {:halt, :ok}

        {:error, reason} ->
          if attempt == max_attempts do
            raise "Services failed to start after #{max_attempts} attempts: #{reason}"
          else
            IO.puts("Attempt #{attempt}/#{max_attempts}: Services not ready yet...")
            Process.sleep(delay_ms)
            {:cont, nil}
          end
      end
    end)
  end

  defp check_postgres_health do
    {_output, exit_code} =
      System.cmd(
        "docker-compose",
        ["exec", "-T", "db", "pg_isready", "-U", "user"],
        stderr_to_stdout: true,
        cd: Path.expand("../integration/jit-access", __DIR__)
      )

    if exit_code == 0 do
      :ok
    else
      {:error, "pg_isready returned non-zero"}
    end
  end

  defp check_service_health do
    # Check if services are responding
    # Adjust these URLs to match your docker-compose services
    services = [
      {"API Service", &check_api_health/0},
      {"PostgreSQL", &check_postgres_health/0}
    ]

    results =
      Enum.map(services, fn {name, check_fn} ->
        case check_fn.() do
          :ok -> {:ok, name}
          {:error, reason} -> {:error, "#{name}: #{reason}"}
        end
      end)

    case Enum.find(results, fn result -> match?({:error, _}, result) end) do
      nil -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_api_health do
    case Req.get("http://localhost:8080/health", receive_timeout: 5000, retry: false) do
      {:ok, %Req.Response{status: status}} when status in 200..299 ->
        :ok

      {:ok, %Req.Response{status: status}} ->
        {:error, "returned status #{status}"}

      {:error, exception} ->
        {:error, Exception.message(exception)}
    end
  end

  def api_client do
    Req.new(
      base_url: "http://localhost:8080",
      headers: [{"content-type", "application/json"}]
    )
  end

  def api_request(method, path, opts \\ []) do
    client = api_client()

    case method do
      :get -> Req.get(client, Keyword.merge([url: path, retry: false], opts))
      :post -> Req.post(client, Keyword.merge([url: path, retry: false], opts))
      :put -> Req.put(client, Keyword.merge([url: path, retry: false], opts))
      :delete -> Req.delete(client, Keyword.merge([url: path, retry: false], opts))
    end
  end
end
