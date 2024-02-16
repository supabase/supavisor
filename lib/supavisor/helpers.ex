defmodule Supavisor.Helpers do
  @moduledoc false
  require Logger

  @spec check_creds_get_ver(map) :: {:ok, String.t() | nil} | {:error, String.t()}

  def check_creds_get_ver(%{"require_user" => false} = params) do
    cond do
      length(params["users"]) != 1 ->
        {:error, "Can't use 'require_user' and 'auth_query' with multiple users"}

      !hd(params["users"])["is_manager"] ->
        {:error, "Can't use 'require_user' and 'auth_query' with non-manager user"}

      true ->
        do_check_creds_get_ver(params)
    end
  end

  def check_creds_get_ver(%{"users" => _} = params) do
    do_check_creds_get_ver(params)
  end

  def check_creds_get_ver(_), do: {:ok, nil}

  def do_check_creds_get_ver(params) do
    Enum.reduce_while(params["users"], {nil, nil}, fn user, _ ->
      upstream_ssl? = !!params["upstream_ssl"]

      ssl_opts =
        if upstream_ssl? and params["upstream_verify"] == "peer" do
          [
            {:verify, :verify_peer},
            {:cacerts, [upstream_cert(params["upstream_tls_ca"])]},
            {:server_name_indication, String.to_charlist(params["db_host"])},
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
          queue_target: 1_000,
          queue_interval: 5_000,
          ssl_opts: ssl_opts || []
        )

      check =
        Postgrex.query(conn, "select version()", [])
        |> case do
          {:ok, %{rows: [[version]]}} ->
            if !params["require_user"] do
              case get_user_secret(conn, params["auth_query"], user["db_user"]) do
                {:ok, _} ->
                  {:halt, {:ok, version}}

                {:error, reason} ->
                  {:halt, {:error, reason}}
              end
            else
              {:cont, {:ok, version}}
            end

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

  @spec get_user_secret(pid(), String.t(), String.t()) :: {:ok, map()} | {:error, String.t()}
  def get_user_secret(conn, auth_query, user) do
    try do
      Postgrex.query!(conn, auth_query, [user])
    catch
      _error, reason ->
        {:error, "Authentication query failed: #{inspect(reason)}"}
    end
    |> case do
      %{columns: [_, _], rows: [[^user, secret]]} ->
        parse_secret(secret, user)

      %{columns: [_, _], rows: []} ->
        {:error,
         "There is no user '#{user}' in the database. Please create it or change the user in the config"}

      %{columns: colums} ->
        {:error,
         "Authentification query returned wrong format. Should be two columns: user and secret, but got: #{inspect(colums)}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec parse_secret(String.t(), String.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_secret("SCRAM-SHA-256" <> _ = secret, user) do
    # <digest>$<iteration>:<salt>$<stored_key>:<server_key>
    case Regex.run(~r/^(.+)\$(\d+):(.+)\$(.+):(.+)$/, secret) do
      [_, digest, iterations, salt, stored_key, server_key] ->
        {:ok,
         %{
           digest: digest,
           iterations: String.to_integer(iterations),
           salt: salt,
           stored_key: Base.decode64!(stored_key),
           server_key: Base.decode64!(server_key),
           user: user
         }}

      _ ->
        {:error, "Can't parse secret"}
    end
  end

  def parse_secret("md5" <> secret, user) do
    {:ok, %{digest: :md5, secret: secret, user: user}}
  end

  def parse_postgres_secret(_), do: {:error, "Digest not supported"}

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

  @spec downstream_cert() :: Path.t() | nil
  def downstream_cert() do
    Application.get_env(:supavisor, :global_downstream_cert)
  end

  @spec downstream_key() :: Path.t() | nil
  def downstream_key() do
    Application.get_env(:supavisor, :global_downstream_key)
  end

  @spec get_client_final(:password | :auth_query, map(), map(), binary(), binary(), binary()) ::
          {iolist(), binary()}
  def get_client_final(
        :password,
        secrets,
        srv_first,
        client_nonce,
        user_name,
        channel
      ) do
    channel_binding = "c=#{channel}"
    nonce = ["r=", srv_first.nonce]

    salt = srv_first.salt
    i = srv_first.i

    salted_password = :pgo_scram.hi(:pgo_sasl_prep_profile.validate(secrets), salt, i)
    client_key = :pgo_scram.hmac(salted_password, "Client Key")
    stored_key = :pgo_scram.h(client_key)
    client_first_bare = [<<"n=">>, user_name, <<",r=">>, client_nonce]
    server_first = srv_first.raw
    client_final_without_proof = [channel_binding, ",", nonce]
    auth_message = [client_first_bare, ",", server_first, ",", client_final_without_proof]
    client_signature = :pgo_scram.hmac(stored_key, auth_message)
    client_proof = :pgo_scram.bin_xor(client_key, client_signature)

    server_key = :pgo_scram.hmac(salted_password, "Server Key")
    server_signature = :pgo_scram.hmac(server_key, auth_message)

    {[client_final_without_proof, ",p=", Base.encode64(client_proof)], server_signature}
  end

  def get_client_final(
        :auth_query,
        secrets,
        srv_first,
        client_nonce,
        user_name,
        channel
      ) do
    channel_binding = "c=#{channel}"
    nonce = ["r=", srv_first.nonce]

    client_first_bare = [<<"n=">>, user_name, <<",r=">>, client_nonce]
    server_first = srv_first.raw
    client_final_without_proof = [channel_binding, ",", nonce]
    auth_message = [client_first_bare, ",", server_first, ",", client_final_without_proof]
    client_signature = :pgo_scram.hmac(secrets.stored_key, auth_message)
    client_proof = :pgo_scram.bin_xor(secrets.client_key, client_signature)

    server_signature = :pgo_scram.hmac(secrets.server_key, auth_message)

    {[client_final_without_proof, ",p=", Base.encode64(client_proof)], server_signature}
  end

  def signatures(stored_key, server_key, srv_first, client_nonce, user_name, channel) do
    channel_binding = "c=#{channel}"
    nonce = ["r=", srv_first.nonce]
    client_first_bare = [<<"n=">>, user_name, <<",r=">>, client_nonce]
    server_first = srv_first.raw
    client_final_without_proof = [channel_binding, ",", nonce]
    auth_message = [client_first_bare, ",", server_first, ",", client_final_without_proof]

    %{
      client: :pgo_scram.hmac(stored_key, auth_message),
      server: :pgo_scram.hmac(server_key, auth_message)
    }
  end

  def hash(bin) do
    :crypto.hash(:sha256, bin)
  end

  @spec parse_server_first(binary(), binary()) :: map()
  def parse_server_first(message, nonce) do
    :pgo_scram.parse_server_first(message, nonce) |> Map.new()
  end

  @spec md5([String.t()]) :: String.t()
  def md5(strings) do
    strings
    |> :erlang.md5()
    |> Base.encode16(case: :lower)
  end

  @spec rpc(Node.t(), module(), atom(), [any()], non_neg_integer()) :: {:error, any()} | any()
  def rpc(node, module, function, args, timeout \\ 15_000) do
    try do
      :erpc.call(node, module, function, args, timeout)
      |> case do
        {:EXIT, _} = badrpc -> {:error, {:badrpc, badrpc}}
        result -> result
      end
    catch
      kind, reason -> {:error, {:badrpc, {kind, reason}}}
    end
  end

  @doc """
  Sets the maximum heap size for the current process. The `max_heap_size` parameter is in megabytes.

  ## Parameters

  - `max_heap_size`: The maximum heap size in megabytes.
  """
  @spec set_max_heap_size(pos_integer()) :: map()
  def set_max_heap_size(max_heap_size) do
    max_heap_words = div(max_heap_size * 1024 * 1024, :erlang.system_info(:wordsize))
    Process.flag(:max_heap_size, %{size: max_heap_words})
  end

  @spec set_log_level(atom()) :: :ok
  def set_log_level(nil), do: :ok

  def set_log_level(level) when is_atom(level) do
    Logger.notice("Setting log level to #{inspect(level)}")
    Logger.put_process_level(self(), level)
  end
end
