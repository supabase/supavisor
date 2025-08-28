defmodule Supavisor.PostgresCase do
  @moduledoc """
  Test case for integration tests that require Dockerized Postgres containers.
  Provides helpers for starting/stopping containers.
  """

  use ExUnit.CaseTemplate

  @default_postgres_image "postgres:15"
  @default_postgres_container_name "test_postgres"
  @default_postgres_port 7432
  @default_postgres_user "postgres"
  @default_postgres_password "postgres"
  @default_postgres_db "postgres"

  using do
    quote do
      import unquote(__MODULE__)
    end
  end

  def start_postgres_container(opts) do
    image = opts[:image] || @default_postgres_image
    container_name = opts[:container_name] || @default_postgres_container_name
    port = opts[:port] || @default_postgres_port
    user = opts[:username] || @default_postgres_user
    password = opts[:password] || @default_postgres_password
    db = opts[:database] || @default_postgres_db
    volume = opts[:volume]
    environment = opts[:environment]

    cmd = [
      "run",
      "-d",
      "--name",
      container_name,
      "-e",
      "POSTGRES_USER=#{user}",
      "-e",
      "POSTGRES_PASSWORD=#{password}",
      "-e",
      "POSTGRES_DB=#{db}",
      "-p",
      "#{port}:5432"
    ]

    cmd = if volume, do: cmd ++ ["-v", volume], else: cmd
    cmd = if environment, do: cmd ++ ["-e", "POSTGRES_INITDB_ARGS=#{environment}"], else: cmd
    cmd = cmd ++ [image]

    {_output, 0} = System.cmd("docker", cmd)

    wait_for_postgres(%{port: port, username: user, database: db})
  end

  defp wait_for_postgres(opts, max_attempts \\ 30), do: wait_for_postgres(opts, 1, max_attempts)

  defp wait_for_postgres(opts, attempt, max_attempts) when attempt != max_attempts do
    case System.cmd("pg_isready", [
           "-h",
           "localhost",
           "-p",
           to_string(opts[:port]),
           "-U",
           opts[:username],
           "-d",
           opts[:database]
         ]) do
      {_, 0} ->
        :ok

      _ ->
        Process.sleep(1000)
        wait_for_postgres(opts, attempt + 1, max_attempts)
    end
  end

  defp wait_for_postgres(_opts, _attempt, max_attempts) do
    raise "PostgreSQL failed to start within #{max_attempts} seconds"
  end

  def stop_postgres_container(container_name) do
    System.cmd("docker", ["stop", container_name])
    System.cmd("docker", ["rm", container_name])
    :ok
  end

  def cleanup_containers(names) when is_list(names) do
    Enum.each(names, fn name -> cleanup_containers(name) end)
  end

  def cleanup_containers(name) when is_binary(name) do
    System.cmd("docker", ["rm", "-f", name], stderr_to_stdout: true)
  end
end
