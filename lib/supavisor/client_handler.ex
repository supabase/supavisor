defmodule Supavisor.ClientHandler do
  @moduledoc """
  This module is responsible for handling incoming connections to the Supavisor server. It is
  implemented as a Ranch protocol behavior and a gen_statem behavior. It handles SSL negotiation,
  user authentication, tenant subscription, and dispatching of messages to the appropriate tenant
  supervisor. Each client connection is assigned to a specific tenant supervisor.
  """

  @type tcp_sock :: {:gen_tcp, :gen_tcp.socket()}
  @type ssl_sock :: {:ssl, :ssl.sslsocket()}
  @type sock :: tcp_sock() | ssl_sock()

  require Logger

  @behaviour :ranch_protocol
  @behaviour :gen_statem

  alias Supavisor.DbHandler, as: Db
  alias Supavisor.Helpers, as: H
  alias Supavisor.{Tenants, Protocol.Server, Monitoring.Telem}

  @impl true
  def start_link(ref, _sock, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  def client_call(pid, bin, ready?) do
    :gen_statem.call(pid, {:client_call, bin, ready?}, 5000)
  end

  @impl true
  def init(_), do: :ignore

  def init(ref, trans, _opts) do
    Process.flag(:trap_exit, true)

    {:ok, sock} = :ranch.handshake(ref)
    :ok = trans.setopts(sock, active: true)
    Logger.debug("ClientHandler is: #{inspect(self())}")

    data = %{
      sock: {:gen_tcp, sock},
      trans: trans,
      db_pid: nil,
      tenant: nil,
      user_alias: nil,
      pool: nil,
      manager: nil,
      query_start: nil,
      mode: nil,
      timeout: nil,
      ps: nil,
      ssl: false,
      auth_secrets: nil
    }

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :exchange, data)
  end

  @impl true
  def handle_event(:info, {_proto, _, <<"GET", _::binary>>}, :exchange, data) do
    Logger.debug("Client is trying to request HTTP")
    sock_send(data.sock, "HTTP/1.1 204 OK\r\n\r\n")
    {:stop, :normal, data}
  end

  def handle_event(:info, {:tcp, _, <<_::64>>}, :exchange, %{sock: sock} = data) do
    Logger.debug("Client is trying to connect with SSL")

    downstream_cert = H.downstream_cert()
    downstream_key = H.downstream_key()

    # SSL negotiation, S/N/Error
    if !!downstream_cert and !!downstream_key do
      :ok = setopts(sock, active: false)
      :ok = sock_send(sock, "S")

      opts = [
        certfile: downstream_cert,
        keyfile: downstream_key
      ]

      case :ssl.handshake(elem(sock, 1), opts) do
        {:ok, ssl_sock} ->
          socket = {:ssl, ssl_sock}
          :ok = setopts(socket, active: true)
          {:keep_state, %{data | sock: socket, ssl: true}}

        error ->
          Logger.error("SSL handshake error: #{inspect(error)}")
          {:stop, :normal, data}
      end
    else
      Logger.error("User requested SSL connection but no downstream cert/key found")
      :ok = sock_send(data.sock, "N")
      :keep_state_and_data
    end
  end

  def handle_event(:info, {_proto, _, bin}, :exchange, %{sock: sock} = data) do
    hello = decode_startup_packet(bin)
    Logger.warning("Client startup message: #{inspect(hello)}")
    {user, external_id} = parse_user_info(hello.payload["user"])
    Logger.metadata(project: external_id, user: user)

    case Tenants.get_user(external_id, user) do
      {:ok, info} ->
        if info.tenant.enforce_ssl and !data.ssl do
          Logger.error("Tenant is not allowed to connect without SSL, user #{user}")
          :ok = send_error(sock, "XX000", "SSL connection is required")
          {:stop, :normal, data}
        else
          new_data = update_user_data(data, external_id, info)

          case auth_secrets(info, user) do
            {:ok, auth_secrets} ->
              Logger.debug("Authentication method: #{inspect(auth_secrets)}")
              {:keep_state, new_data, {:next_event, :internal, {:handle, auth_secrets}}}

            {:error, reason} ->
              Logger.error("Authentication auth_secrets error: #{inspect(reason)}")

              :ok = send_error(sock, "XX000", "Authentication error")
              {:stop, :normal, data}
          end
        end

      {:error, reason} ->
        Logger.error("User not found: #{inspect(reason)} #{inspect({user, external_id})}")

        :ok = send_error(sock, "XX000", "Tenant or user not found")
        {:stop, :normal, data}
    end
  end

  def handle_event(:internal, {:handle, {method, secrets}}, _, %{sock: sock} = data) do
    Logger.info("Handle exchange, auth method: #{inspect(method)}")

    case handle_exchange(sock, {method, secrets}, data.ssl) do
      {:error, reason} ->
        Logger.error("Exchange error: #{inspect(reason)}")
        msg = Server.exchange_message(:final, "e=#{reason}")
        sock_send(sock, msg)

        {:stop, :normal, data}

      {:ok, client_key} ->
        secrets =
          if client_key do
            fn ->
              Map.put(secrets.(), :client_key, client_key)
            end
          else
            nil
          end

        Logger.info("Exchange success")
        :ok = sock_send(sock, Server.authentication_ok())

        {:keep_state, %{data | auth_secrets: secrets}, {:next_event, :internal, :subscribe}}
    end
  end

  def handle_event(:internal, :subscribe, _, %{tenant: tenant, user_alias: db_alias} = data) do
    Logger.info("Subscribe to tenant #{inspect({tenant, db_alias})}")

    with {:ok, tenant_sup} <- Supavisor.start(tenant, db_alias, data.auth_secrets),
         {:ok, %{manager: manager, pool: pool}, ps} <-
           Supavisor.subscribe_global(node(tenant_sup), self(), tenant, db_alias) do
      Process.monitor(manager)
      data = %{data | manager: manager, pool: pool}
      db_pid = db_checkout(:on_connect, data)
      data = %{data | db_pid: db_pid}

      if ps == [] do
        {:keep_state, data, {:timeout, 10_000, :wait_ps}}
      else
        {:keep_state, data, {:next_event, :internal, {:greetings, ps}}}
      end
    else
      error ->
        Logger.error("Subscribe error: #{inspect(error)}")
        {:keep_state_and_data, {:timeout, 1000, :subscribe}}
    end
  end

  def handle_event(:internal, {:greetings, ps}, _, %{sock: sock} = data) do
    :ok = sock_send(sock, Server.greetings(ps))
    {:next_state, :idle, data}
  end

  def handle_event(:timeout, :subscribe, _, _) do
    {:keep_state_and_data, {:next_event, :internal, :subscribe}}
  end

  def handle_event(:timeout, :wait_ps, _, data) do
    Logger.error("Wait parameter status timeout, send default #{inspect(data.ps)}}")

    ps = Server.encode_parameter_status(data.ps)
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  # ignore termination messages
  def handle_event(:info, {proto, _, <<?X, 4::32>>}, _, _) when proto in [:tcp, :ssl] do
    Logger.warn("Receive termination")
    :keep_state_and_data
  end

  def handle_event(:info, {proto, _, bin}, :idle, data) do
    ts = System.monotonic_time()
    db_pid = db_checkout(:on_query, data)

    {:next_state, :busy, %{data | db_pid: db_pid, query_start: ts},
     {:next_event, :internal, {proto, nil, bin}}}
  end

  def handle_event(_, {proto, _, bin}, :busy, data) when proto in [:tcp, :ssl] do
    case Db.call(data.db_pid, bin) do
      :ok ->
        Logger.info("DB call success")
        :keep_state_and_data

      {:buffering, size} ->
        Logger.warn("DB call buffering #{size}}")

        if size > 1_000_000 do
          msg = "Db buffer size is too big: #{size}"
          Logger.error(msg)
          sock_send(data.sock, Server.error_message("XX000", msg))
          {:stop, :normal, data}
        else
          Logger.debug("DB call buffering")
          :keep_state_and_data
        end

      {:error, reason} ->
        msg = "DB call error: #{inspect(reason)}"
        Logger.error(msg)
        sock_send(data.sock, Server.error_message("XX000", msg))
        {:stop, :normal, data}
    end
  end

  def handle_event(:info, {:parameter_status, :updated}, _, data) do
    Logger.warning("Parameter status is updated")
    {:stop, :normal, data}
  end

  def handle_event(:info, {:parameter_status, ps}, :exchange, _) do
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  # client closed connection
  def handle_event(_, {:tcp_closed, _}, _, data) do
    Logger.debug("tcp soket closed for #{inspect(data.tenant)}")
    {:stop, :normal}
  end

  def handle_event(_, {closed, _}, _, data)
      when closed in [:tcp_closed, :ssl_closed] do
    Logger.debug("#{closed} soket closed for #{inspect(data.tenant)}")
    {:stop, :normal}
  end

  # linked db_handler went down
  def handle_event(:info, {:EXIT, db_pid, reason}, _, _) do
    Logger.error("DB handler #{inspect(db_pid)} exited #{inspect(reason)}")
    {:stop, :normal}
  end

  # pool's manager went down
  def handle_event(:info, {:DOWN, _, _, _, reason}, state, data) do
    Logger.error(
      "Manager #{inspect(data.manager)} went down #{inspect(reason)} state #{inspect(state)}"
    )

    case state do
      :idle ->
        {:keep_state_and_data, {:next_event, :internal, :subscribe}}

      :busy ->
        {:stop, :normal}
    end
  end

  # emulate handle_call
  def handle_event({:call, from}, {:client_call, bin, ready?}, _, data) do
    Logger.debug("--> --> bin #{inspect(byte_size(bin))} bytes")

    reply = {:reply, from, sock_send(data.sock, bin)}

    if ready? do
      Logger.debug("Client is ready")

      db_pid = handle_db_pid(data.mode, data.pool, data.db_pid)

      Telem.network_usage(:client, data.sock, data.tenant, data.user_alias)
      Telem.client_query_time(data.query_start, data.tenant, data.user_alias)
      {:next_state, :idle, %{data | db_pid: db_pid}, reply}
    else
      Logger.debug("Client is not ready")
      {:keep_state_and_data, reply}
    end
  end

  def handle_event(type, content, state, data) do
    msg = [
      {"type", type},
      {"content", content},
      {"state", state},
      {"data", data}
    ]

    Logger.debug("Undefined msg: #{inspect(msg, pretty: true)}")

    :keep_state_and_data
  end

  @impl true
  def terminate(
        {:timeout, {_, _, [_, {:checkout, _, _}, _]}},
        _,
        data
      ) do
    msg =
      case data.mode do
        :session ->
          "Too many clients already"

        :transaction ->
          "Unable to check out process from the pool due to timeout"
      end

    Logger.error(msg)
    sock_send(data.sock, Server.error_message("XX000", msg))
    :ok
  end

  def terminate(_reason, _state, _data), do: :ok

  ## Internal functions

  @spec parse_user_info(String.t()) :: {String.t() | nil, String.t()}
  def parse_user_info(username) do
    case :binary.matches(username, ".") do
      [] ->
        {nil, username}

      matches ->
        {pos, _} = List.last(matches)
        {name, "." <> external_id} = String.split_at(username, pos)
        {name, external_id}
    end
  end

  def decode_startup_packet(<<len::integer-32, _protocol::binary-4, rest::binary>>) do
    %{
      len: len,
      payload:
        String.split(rest, <<0>>, trim: true)
        |> Enum.chunk_every(2)
        |> Enum.into(%{}, fn [k, v] -> {k, v} end),
      tag: :startup
    }
  end

  def decode_startup_packet(_) do
    :undef
  end

  @spec handle_exchange(sock(), {atom(), fun()}, boolean()) ::
          {:ok, binary() | nil} | {:error, String.t()}
  def handle_exchange({_, socket} = sock, {method, secrets}, ssl) do
    :ok = sock_send(sock, Server.auth_request())

    receive do
      {_proto, ^socket, bin} ->
        case Server.decode_pkt(bin) do
          {:ok,
           %{
             tag: :password_message,
             payload: {:scram_sha_256, %{"n" => user, "r" => nonce}}
           }, _} ->
            channel = if ssl, do: "eSws", else: "biws"
            {message, signatures} = exchange_first(method, secrets, nonce, user, channel)
            :ok = sock_send(sock, Server.exchange_message(:first, message))

            receive do
              {_proto, ^socket, bin} ->
                case Server.decode_pkt(bin) do
                  {:ok,
                   %{
                     tag: :password_message,
                     payload: {:first_msg_response, %{"p" => p}}
                   }, _}
                  when method == :password ->
                    if p == signatures.client do
                      message = "v=#{Base.encode64(signatures.server)}"

                      :ok = sock_send(sock, Server.exchange_message(:final, message))

                      {:ok, nil}
                    else
                      {:error, "Invalid client signature"}
                    end

                  {:ok,
                   %{
                     tag: :password_message,
                     payload: {:first_msg_response, %{"p" => p}}
                   }, _}
                  when method == :auth_query ->
                    client_key = :crypto.exor(p |> Base.decode64!(), signatures.client)

                    if H.hash(client_key) == secrets.().stored_key do
                      message = "v=#{Base.encode64(signatures.server)}"

                      :ok =
                        sock_send(
                          sock,
                          Server.exchange_message(:final, message)
                        )

                      {:ok, client_key}
                    else
                      {:error, "Invalid client signature"}
                    end

                  other ->
                    {:error, "Unexpected message #{inspect(other)}"}
                end

              other ->
                {:error, "Unexpected message #{inspect(other)}"}
            after
              15_000 ->
                {:error, "Timeout while waiting for the second password message"}
            end

          other ->
            {:error, "Unexpected message #{inspect(other)}"}
        end
    after
      15_000 ->
        {:error, "Timeout while waiting for the first password message"}
    end
  end

  @spec db_checkout(:on_connect | :on_query, map()) :: pid() | nil
  defp db_checkout(_, %{mode: :session, db_pid: db_pid}) when is_pid(db_pid) do
    db_pid
  end

  defp db_checkout(:on_connect, %{mode: :transaction}), do: nil

  defp db_checkout(_, data) do
    {time, db_pid} = :timer.tc(:poolboy, :checkout, [data.pool, true, data.timeout])
    Process.link(db_pid)
    Telem.pool_checkout_time(time, data.tenant, data.user_alias)
    db_pid
  end

  @spec handle_db_pid(:transaction, pid(), pid()) :: nil
  @spec handle_db_pid(:session, pid(), pid()) :: pid()
  defp handle_db_pid(:transaction, pool, db_pid) do
    Process.unlink(db_pid)
    :poolboy.checkin(pool, db_pid)
    nil
  end

  defp handle_db_pid(:session, _, db_pid), do: db_pid

  defp update_user_data(data, external_id, info) do
    %{
      data
      | tenant: external_id,
        user_alias: info.user.db_user_alias,
        mode: info.user.mode_type,
        timeout: info.user.pool_checkout_timeout,
        ps: info.tenant.default_parameter_status
    }
  end

  @spec sock_send(tcp_sock() | ssl_sock(), iodata()) :: :ok | {:error, term()}
  defp sock_send({mod, sock}, data) do
    mod.send(sock, data)
  end

  @spec send_error(sock, String.t(), String.t()) :: :ok | {:error, term()}
  defp send_error(sock, code, message) do
    data = Server.error_message(code, message)
    sock_send(sock, data)
  end

  @spec setopts(sock, term()) :: :ok | {:error, term()}
  defp setopts({mod, sock}, opts) do
    mod = if mod == :gen_tcp, do: :inet, else: mod
    mod.setopts(sock, opts)
  end

  @spec auth_secrets(map, String.t()) ::
          {:ok, {:password | :auth_query, fun()}} | {:error, term()}
  def auth_secrets(%{user: user, tenant: %{require_user: true}}, _) do
    {:ok, {:password, fn -> user.db_password end}}
  end

  def auth_secrets(%{user: user, tenant: tenant} = info, db_user) do
    cache_key = {:secrets, tenant.external_id, user}

    case Cachex.fetch(Supavisor.Cache, cache_key, fn _key ->
           {resp, ttl} =
             case get_secrets(info, db_user) do
               {:ok, _} = ok ->
                 # cache for 1 hour
                 {ok, :timer.seconds(3600)}

               error ->
                 {error, :timer.seconds(15)}
             end

           {:commit, {:cached, resp}, ttl: ttl}
         end) do
      {_, {:cached, value}} ->
        value

      {_, {:cached, value}, _} ->
        value
    end
  end

  @spec get_secrets(map, String.t()) :: {:ok, {:auth_query, fun()}} | {:error, term()}
  def get_secrets(%{user: user, tenant: tenant}, db_user) do
    ssl_opts =
      if tenant.upstream_ssl and tenant.upstream_verify == "peer" do
        [
          {:verify, :verify_peer},
          {:cacerts, [H.upstream_cert(tenant.upstream_tls_ca)]},
          {:customize_hostname_check, [{:match_fun, fn _, _ -> true end}]}
        ]
      end

    {:ok, conn} =
      Postgrex.start_link(
        hostname: tenant.db_host,
        port: tenant.db_port,
        database: tenant.db_database,
        password: user.db_password,
        username: user.db_user,
        ssl: tenant.upstream_ssl,
        socket_options: [
          H.ip_version(tenant.ip_version, tenant.db_host)
        ],
        ssl_opts: ssl_opts || []
      )

    resp =
      case H.get_user_secret(conn, tenant.auth_query, db_user) do
        {:ok, secret} ->
          {:ok, {:auth_query, fn -> secret end}}

        {:error, reason} ->
          {:error, reason}
      end

    GenServer.stop(conn, :normal)
    resp
  end

  @spec exchange_first(:password | :auth_query, fun(), binary(), binary(), binary()) ::
          {binary(), map()}
  defp exchange_first(:password, secret, nonce, user, channel) do
    message = Server.exchange_first_message(nonce)
    server_first_parts = :pgo_scram.parse_server_first(message, nonce)

    {client_final_message, server_proof} =
      H.get_client_final(
        :password,
        secret.(),
        server_first_parts,
        nonce,
        user,
        channel
      )

    sings = %{
      client: List.last(client_final_message),
      server: server_proof
    }

    {message, sings}
  end

  defp exchange_first(:auth_query, secret, nonce, user, channel) do
    secret = secret.()
    message = Server.exchange_first_message(nonce, secret.salt)
    server_first_parts = :pgo_scram.parse_server_first(message, nonce)

    sings =
      H.signatures(
        secret.stored_key,
        secret.server_key,
        server_first_parts,
        nonce,
        user,
        channel
      )

    {message, sings}
  end
end
