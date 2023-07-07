defmodule Supavisor.Helpers do
  @moduledoc false

  @spec check_creds_get_ver(map) :: {:ok, String.t()} | {:error, String.t()}
  def check_creds_get_ver(params) do
    Enum.reduce_while(params["users"], {nil, nil}, fn user, _ ->
      upstream_ssl? = !!params["upstream_ssl"]

      ssl_opts =
        if upstream_ssl? and params["upstream_verify"] == "peer" do
          [
            {:verify, :verify_peer},
            {:cacerts, [upstream_cert(params["upstream_tls_ca"])]},
            {:customize_hostname_check, [{:match_fun, fn _, _ -> true end}]}
          ]
        end

      {:ok, conn} =
        Postgrex.start_link(
          hostname: params["db_host"],
          port: params["db_port"],
          database: params["db_database"],
          password: user["db_password"],
          username: user["db_user"],
          ssl: upstream_ssl?,
          socket_options: [
            ip_version(params["ip_version"], params["db_host"])
          ],
          ssl_opts: ssl_opts || []
        )

      check =
        Postgrex.query(conn, "select version()", [])
        |> case do
          {:ok, %{rows: [[version]]}} ->
            {:cont, {:ok, version}}

          {:error, reason} ->
            {:halt, {:error, "Can't connect the user #{user["db_user"]}: #{inspect(reason)}"}}
        end

      GenServer.stop(conn)
      check
    end)
    |> case do
      {:ok, version} ->
        parse_pg_version(version)

      other ->
        other
    end
  end

  ## Internal functions

  @doc """
  Parses a PostgreSQL version string and returns the version number and platform.

  ## Examples

      iex> Supavisor.Helpers.parse_pg_version("PostgreSQL 14.6 (Debian 14.6-1.pgdg110+1) some string")
      {:ok, "14.6 (Debian 14.6-1.pgdg110+1)"}

      iex> Supavisor.Helpers.parse_pg_version("PostgreSQL 15.1 on aarch64-unknown-linux-gnu, compiled by gcc (Ubuntu 10.3.0-1ubuntu1~20.04) 10.3.0, 64-bit")
      {:ok, "15.1"}

      iex> Supavisor.Helpers.parse_pg_version("PostgreSQL on x86_64-pc-linux-gnu")
      {:error, "Can't parse version in PostgreSQL on x86_64-pc-linux-gnu"}
  """
  def parse_pg_version(version) do
    case Regex.run(~r/PostgreSQL\s(\d+\.\d+)(?:\s\(([^)]+)\))?.*/, version) do
      [_, version, platform] ->
        {:ok, "#{version} (#{platform})"}

      [_, version] ->
        {:ok, version}

      _ ->
        {:error, "Can't parse version in #{version}"}
    end
  end

  @doc """
  Returns the IP version for a given host.

  ## Examples

      iex> Supavisor.Helpers.ip_version(:v4, "example.com")
      :inet
      iex> Supavisor.Helpers.ip_version(:v6, "example.com")
      :inet6
      iex> Supavisor.Helpers.ip_version(nil, "example.com")
      :inet
  """
  @spec ip_version(any(), String.t()) :: :inet | :inet6
  def ip_version(:v4, _), do: :inet
  def ip_version(:v6, _), do: :inet6

  def ip_version(_, host) do
    detect_ip_version(host)
  end

  @doc """
  Detects the IP version for a given host.

  ## Examples

      iex> Supavisor.Helpers.detect_ip_version("example.com")
      :inet
      iex> Supavisor.Helpers.detect_ip_version("ipv6.example.com")
      :inet6
  """
  @spec detect_ip_version(String.t()) :: :inet | :inet6
  def detect_ip_version(host) when is_binary(host) do
    host = String.to_charlist(host)

    case :inet.gethostbyname(host) do
      {:ok, _} -> :inet
      _ -> :inet6
    end
  end

  @spec cert_to_bin(binary()) :: {:ok, binary()} | {:error, atom()}
  def cert_to_bin(cert) do
    case :public_key.pem_decode(cert) do
      [] ->
        {:error, :cant_decode_certificate}

      pem_entries ->
        cert = for {:Certificate, cert, :not_encrypted} <- pem_entries, do: cert

        case cert do
          [cert] -> {:ok, cert}
          _ -> {:error, :invalid_certificate}
        end
    end
  end

  @spec upstream_cert(binary() | nil) :: binary() | nil
  def upstream_cert(default) do
    Application.get_env(:supavisor, :global_upstream_ca) || default
  end
end
