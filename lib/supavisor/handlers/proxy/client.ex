defmodule Supavisor.Handlers.Proxy.Client do
  @moduledoc false

  require Logger

  alias Supavisor.{
    Tenants,
    Helpers,
    DbHandler,
    HandlerHelpers,
    Protocol.Server,
    Monitoring.Telem,
    Handlers.Proxy.Db
  }

  @cancel_query_msg <<16::32, 1234::16, 5678::16>>
  @sock_closed [:tcp_closed, :ssl_closed]
  @proto [:tcp, :ssl]

  def handle_event(:info, {_proto, _, <<"GET", _::binary>>}, :exchange, data) do
    Logger.debug("ProxyClient: Client is trying to request HTTP")

    HandlerHelpers.sock_send(
      data.sock,
      "HTTP/1.1 204 OK\r\nx-app-version: #{data.version}\r\n\r\n"
    )

    {:stop, {:shutdown, :http_request}}
  end

  # cancel request
  def handle_event(:info, {_, _, <<@cancel_query_msg, pid::32, key::32>>}, _, _) do
    Logger.debug("ProxyClient: Got cancel query for #{inspect({pid, key})}")
    :ok = HandlerHelpers.send_cancel_query(pid, key, {:client, :cancel_query})
    {:stop, {:shutdown, :cancel_query}}
  end

  def handle_event(:info, {:client, :cancel_query}, _, %{db_pid: db_pid})
      when is_pid(db_pid) do
    Logger.debug("ProxyClient: Cancel query for #{inspect(db_pid)}")

    case db_pid_meta(db_pid) do
      [{^db_pid, meta}] ->
        :ok = HandlerHelpers.cancel_query(meta.host, meta.port, meta.ip_ver, meta.pid, meta.key)

      error ->
        Logger.error(
          "ClientHandler: Received cancel but no proc was found #{inspect(db_pid)} #{inspect(error)}"
        )
    end

    :keep_state_and_data
  end

  def handle_event(:info, {:client, :cancel_query}, _, %{
        auth: auth,
        backend_key_data: b
      }) do
    :ok = HandlerHelpers.cancel_query(~c"#{auth.host}", auth.port, auth.ip_ver, b.pid, b.key)
    :keep_state_and_data
  end

  # # ssl request from client
  def handle_event(:info, {:tcp, _, <<_::64>>}, :exchange, %{sock: sock} = data) do
    Logger.debug("ProxyClient: Client is trying to connect with SSL")

    downstream_cert = Helpers.downstream_cert()
    downstream_key = Helpers.downstream_key()

    # SSL negotiation, S/N/Error
    if !!downstream_cert and !!downstream_key do
      :ok = HandlerHelpers.setopts(sock, active: false)
      :ok = HandlerHelpers.sock_send(sock, "S")

      opts = [
        certfile: downstream_cert,
        keyfile: downstream_key
      ]

      case :ssl.handshake(elem(sock, 1), opts) do
        {:ok, ssl_sock} ->
          socket = {:ssl, ssl_sock}
          :ok = HandlerHelpers.setopts(socket, active: true)
          {:keep_state, %{data | sock: socket, ssl: true}}

        error ->
          Logger.error("ProxyClient: SSL handshake error: #{inspect(error)}")
          Telem.client_join(:fail, data.id)
          {:stop, {:shutdown, :ssl_handshake_error}}
      end
    else
      Logger.error("ProxyClient: User requested SSL connection but no downstream cert/key found")

      :ok = HandlerHelpers.sock_send(data.sock, "N")
      :keep_state_and_data
    end
  end

  def handle_event(:info, {_, _, bin}, :exchange, data) do
    case Server.decode_startup_packet(bin) do
      {:ok, hello} ->
        Logger.debug("ProxyClient: Client startup message: #{inspect(hello)}")
        {type, {user, tenant_or_alias, db_name}} = HandlerHelpers.parse_user_info(hello.payload)

        # Validate user and db_name according to PostgreSQL rules.
        # The rules are: 1-63 characters, alphanumeric, underscore and $
        # TODO: spaces are allowed in db_name, but we don't support it yet
        rule = ~r/^[a-z_][a-z0-9_$]*$/

        if user =~ rule and db_name =~ rule do
          log_level = maybe_change_log(hello)
          event = {:hello, {type, {user, tenant_or_alias, db_name}}}
          app_name = app_name(hello.payload["application_name"])

          {:keep_state, %{data | log_level: log_level, app_name: app_name},
           {:next_event, :internal, {:client, event}}}
        else
          reason = "Invalid format for user or db_name"
          Logger.error("ProxyClient: #{inspect(reason)}")
          Telem.client_join(:fail, tenant_or_alias)

          HandlerHelpers.send_error(
            data.sock,
            "XX000",
            "Authentication error, reason: #{inspect(reason)}"
          )

          {:stop, {:shutdown, :invalid_format}}
        end

      {:error, error} ->
        Logger.error("ProxyClient: Client startup message error: #{inspect(error)}")
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :startup_packet_error}}
    end
  end

  def handle_event(
        :internal,
        {:client, {:hello, {type, {user, tenant_or_alias, db_name}}}},
        :exchange,
        %{sock: sock} = data
      ) do
    sni_hostname = HandlerHelpers.try_get_sni(sock)

    case Tenants.get_user_cache(type, user, tenant_or_alias, sni_hostname) do
      {:ok, info} ->
        db_name = if(db_name != nil, do: db_name, else: info.tenant.db_database)

        id =
          Supavisor.id(
            {type, tenant_or_alias},
            user,
            data.mode,
            info.user.mode_type,
            db_name
          )

        mode = Supavisor.mode(id)

        Logger.metadata(
          project: tenant_or_alias,
          user: user,
          mode: mode,
          type: type,
          db_name: db_name,
          app_name: data.app_name,
          peer_ip: data.peer_ip
        )

        Registry.register(Supavisor.Registry.TenantClients, id, [])

        {:ok, addr} = HandlerHelpers.addr_from_sock(sock)

        cond do
          info.tenant.enforce_ssl and !data.ssl and !data.local ->
            Logger.error(
              "ProxyClient: Tenant is not allowed to connect without SSL, user #{user}"
            )

            :ok = HandlerHelpers.send_error(sock, "XX000", "SSL connection is required")
            Telem.client_join(:fail, id)
            {:stop, {:shutdown, :ssl_required}}

          HandlerHelpers.filter_cidrs(info.tenant.allow_list, addr) == [] ->
            message = "Address not in tenant allow_list: " <> inspect(addr)
            Logger.error("ProxyClient: #{message}")
            :ok = HandlerHelpers.send_error(sock, "XX000", message)

            Telem.client_join(:fail, id)
            {:stop, {:shutdown, :address_not_allowed}}

          true ->
            new_data = update_user_data(data, info, user, id, db_name, mode)

            key = {:secrets, tenant_or_alias, user}

            case auth_secrets(info, user, key, :timer.hours(24)) do
              {:ok, auth_secrets} ->
                Logger.debug("ProxyClient: Authentication method: #{inspect(auth_secrets)}")

                event = {:handle, auth_secrets, info}
                {:keep_state, new_data, {:next_event, :internal, {:client, event}}}

              {:error, reason} ->
                Logger.error("ProxyClient: Authentication auth_secrets error: #{inspect(reason)}")

                :ok =
                  HandlerHelpers.send_error(
                    sock,
                    "XX000",
                    "Authentication error, reason: #{inspect(reason)}"
                  )

                Telem.client_join(:fail, id)
                {:stop, {:shutdown, :auth_secrets_error}}
            end
        end

      {:error, reason} ->
        Logger.error(
          "ProxyClient: User not found: #{inspect(reason)} #{inspect({type, user, tenant_or_alias})}"
        )

        :ok = HandlerHelpers.send_error(sock, "XX000", "Tenant or user not found")
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :user_not_found}}
    end
  end

  def handle_event(
        :internal,
        {:client, {:handle, {method, secrets}, info}},
        _,
        %{sock: sock} = data
      ) do
    Logger.debug("ProxyClient: Handle exchange, auth method: #{inspect(method)}")

    case handle_exchange(sock, {method, secrets}) do
      {:error, reason} ->
        Logger.error(
          "ProxyClient: Exchange error: #{inspect(reason)} when method #{inspect(method)}"
        )

        msg =
          if method == :auth_query_md5,
            do: Server.error_message("XX000", reason),
            else: Server.exchange_message(:final, "e=#{reason}")

        key = {:secrets_check, data.tenant, data.user}

        if method != :password and reason == "Wrong password" and
             Cachex.get(Supavisor.Cache, key) == {:ok, nil} do
          case auth_secrets(info, data.user, key, 15_000) do
            {:ok, {method2, secrets2}} = value ->
              if method != method2 or Map.delete(secrets.(), :client_key) != secrets2.() do
                Logger.warning("ProxyClient: Update secrets and terminate pool")

                Cachex.update(
                  Supavisor.Cache,
                  {:secrets, data.tenant, data.user},
                  {:cached, value}
                )

                Supavisor.stop(data.id)
              else
                Logger.debug("ProxyClient: Cache the same #{inspect(key)}")
              end

            other ->
              Logger.error("ProxyClient: Auth secrets check error: #{inspect(other)}")
          end
        else
          Logger.debug("ProxyClient: Cache hit for #{inspect(key)}")
        end

        HandlerHelpers.sock_send(sock, msg)
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :exchange_error}}

      {:ok, client_key} ->
        secrets =
          if client_key do
            fn ->
              Map.put(secrets.(), :client_key, client_key)
            end
          else
            secrets
          end

        Logger.debug("ProxyClient: Exchange success")
        :ok = HandlerHelpers.sock_send(sock, Server.authentication_ok())
        Telem.client_join(:ok, data.id)

        auth = Map.merge(data.auth, %{secrets: secrets, method: method})

        conn_type =
          case data.mode do
            :transaction -> :subscribe
            :session -> :connect_db
          end

        {:keep_state, %{data | auth_secrets: {method, secrets}, auth: auth},
         {:next_event, :internal, {:client, conn_type}}}
    end
  end

  def handle_event(:internal, {:client, :subscribe}, _, data) do
    Logger.warning("ClientHandler: Subscribe to tenant #{inspect(data.id)}")

    with {:ok, sup} <-
           Supavisor.start_dist(data.id, data.auth_secrets, log_level: data.log_level),
         true <- if(node(sup) == node(), do: true, else: :proxy),
         {:ok, opts} <- Supavisor.subscribe(sup, data.id) do
      Process.monitor(opts.workers.manager)
      data = Map.merge(data, opts.workers)
      data = %{data | idle_timeout: opts.idle_timeout}

      next =
        if opts.ps == [] do
          {:timeout, 10_000, :wait_ps}
        else
          {:next_event, :internal, {:client, {:greetings, opts.ps}}}
        end

      {:keep_state, data, next}
    else
      {:error, :max_clients_reached} ->
        msg = "Max client connections reached"
        Logger.error("ClientHandler: #{msg}")
        :ok = HandlerHelpers.send_error(data.sock, "XX000", msg)
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :max_clients_reached}}

      :proxy ->
        {:ok, %{port: port, host: host}} = Supavisor.get_pool_ranch(data.id)

        auth =
          Map.merge(data.auth, %{
            port: port,
            host: host,
            ip_version: :v4,
            upstream_ssl: false,
            upstream_tls_ca: nil,
            upstream_verify: nil
          })

        data = Map.merge(data, %{auth: auth, mode: :session, proxy: true})
        {:keep_state, data, {:next_event, :internal, {:client, :connect_db}}}

      error ->
        Logger.error("ClientHandler: Subscribe error: #{inspect(error)}")
        {:keep_state_and_data, {:timeout, 1000, :subscribe}}
    end
  end

  def handle_event(:internal, {:client, :connect_db}, _, %{auth: auth} = data) do
    Logger.debug("Try to connect to DB")
    Telem.handler_action(:db_handler, :db_connection, data.id)
    ip_ver = Helpers.ip_version(auth.ip_version, auth.host)

    sock_opts = [
      :binary,
      {:packet, :raw},
      {:active, false},
      {:nodelay, true},
      ip_ver
    ]

    case :gen_tcp.connect(~c"#{auth.host}", auth.port, sock_opts) do
      {:ok, sock} ->
        Logger.debug("ProxyClient: auth #{inspect(data, pretty: true)}")

        case Db.try_ssl_handshake({:gen_tcp, sock}, auth) do
          {:ok, sock} ->
            tenant = if(data.proxy, do: Supavisor.tenant(data.id))

            case Db.send_startup(sock, auth, tenant) do
              :ok ->
                HandlerHelpers.active_once(sock)
                auth = Map.put(auth, :ip_ver, ip_ver)
                {:next_state, :db_authentication, %{data | db_sock: sock, auth: auth}}

              {:error, reason} ->
                Logger.error("ProxyClient: Send startup error #{inspect(reason)}")
                {:stop, {:shutdown, :startup_error}}
            end

          {:error, error} ->
            Logger.error("ProxyClient: Handshake error #{inspect(error)}")
            {:stop, {:shutdown, :handshake_error}}
        end

      other ->
        Logger.error(
          "ProxyClient: Connection failed #{inspect(other)} to #{inspect(auth.host)}:#{inspect(auth.port)}"
        )

        {:stop, {:shutdown, :connection_failed}}
    end
  end

  def handle_event(:internal, {:client, {:greetings, ps}}, _, %{sock: sock} = data) do
    {header, <<pid::32, key::32>> = payload} = Server.backend_key_data()
    msg = [ps, [header, payload], Server.ready_for_query()]
    :ok = HandlerHelpers.listen_cancel_query(pid, key)
    :ok = HandlerHelpers.sock_send(sock, msg)
    HandlerHelpers.active_once(sock)
    Telem.client_connection_time(data.connection_start, data.id)
    {:next_state, :idle, data, handle_actions(data)}
  end

  def handle_event(:timeout, :subscribe, _, _) do
    {:keep_state_and_data, {:next_event, :internal, {:client, :connect_db}}}
  end

  def handle_event(:timeout, :wait_ps, _, data) do
    Logger.error("ProxyClient: Wait parameter status timeout, send default #{inspect(data.ps)}}")

    ps = Server.encode_parameter_status(data.ps)
    {:keep_state_and_data, {:next_event, :internal, {:client, {:greetings, ps}}}}
  end

  def handle_event(:timeout, :idle_terminate, _, data) do
    Logger.warning("ProxyClient: Terminate an idle connection by #{data.idle_timeout} timeout")
    {:stop, {:shutdown, :idle_terminate}}
  end

  def handle_event(:timeout, :heartbeat_check, _, data) do
    Logger.debug("ProxyClient: Send heartbeat to client")
    HandlerHelpers.sock_send(data.sock, Server.application_name())
    {:keep_state_and_data, {:timeout, data.heartbeat_interval, :heartbeat_check}}
  end

  def handle_event(
        :info,
        {proto, _, <<?X, 4::32>>},
        _,
        %{mode: :transaction, db_pid: nil}
      )
      when proto in @proto do
    {:stop, {:shutdown, :terminate_received}}
  end

  # forwards the message to the db
  def handle_event(
        :info,
        {proto, _, bin},
        _,
        %{mode: :transaction, db_pid: nil} = data
      )
      when proto in @proto do
    {time, {db_pid, db_sock}} = :timer.tc(__MODULE__, :checkout, [data.pool, data.timeout])
    same_box = if node(db_pid) == node(), do: :local, else: :remote
    Telem.pool_checkout_time(time, data.id, same_box)
    Logger.debug("ProxyClient: Checkout new db connection #{inspect({db_pid, db_sock})}")

    HandlerHelpers.sock_send(db_sock, bin)
    HandlerHelpers.active_once(data.sock)
    {:keep_state, %{data | db_pid: db_pid, db_sock: db_sock}}
  end

  def handle_event(:info, {proto, _, bin}, _, data) when proto in @proto do
    HandlerHelpers.sock_send(data.db_sock, bin)
    HandlerHelpers.active_once(data.sock)
    :keep_state_and_data
  end

  def handle_event(:info, {:parameter_status, ps}, :exchange, _),
    do: {:keep_state_and_data, {:next_event, :internal, {:client, {:greetings, ps}}}}

  # client closed connection
  def handle_event(_, {closed, _}, _, data)
      when closed in @sock_closed do
    Logger.debug("ProxyClient: #{closed} socket closed for #{inspect(data.tenant)}")
    {:stop, {:shutdown, :socket_closed}}
  end

  ## Internal functions

  @spec handle_exchange(Supavisor.sock(), {atom(), fun()}) ::
          {:ok, binary() | nil} | {:error, String.t()}
  def handle_exchange({_, socket} = sock, {:auth_query_md5 = method, secrets}) do
    salt = :crypto.strong_rand_bytes(4)
    :ok = HandlerHelpers.sock_send(sock, Server.md5_request(salt))

    with {:ok,
          %{
            tag: :password_message,
            payload: {:md5, client_md5}
          }, _} <- receive_next(socket, "Timeout while waiting for the md5 exchange"),
         {:ok, key} <- authenticate_exchange(method, client_md5, secrets.().secret, salt) do
      {:ok, key}
    else
      {:error, message} -> {:error, message}
      other -> {:error, "Unexpected message #{inspect(other)}"}
    end
  end

  def handle_exchange({_, socket} = sock, {method, secrets}) do
    :ok = HandlerHelpers.sock_send(sock, Server.scram_request())

    with {:ok,
          %{
            tag: :password_message,
            payload: {:scram_sha_256, %{"n" => user, "r" => nonce, "c" => channel}}
          },
          _} <-
           receive_next(
             socket,
             "Timeout while waiting for the first password message"
           ),
         {:ok, signatures} = reply_first_exchange(sock, method, secrets, channel, nonce, user),
         {:ok,
          %{
            tag: :password_message,
            payload: {:first_msg_response, %{"p" => p}}
          },
          _} <-
           receive_next(
             socket,
             "Timeout while waiting for the second password message"
           ),
         {:ok, key} <- authenticate_exchange(method, secrets, signatures, p) do
      message = "v=#{Base.encode64(signatures.server)}"
      :ok = HandlerHelpers.sock_send(sock, Server.exchange_message(:final, message))
      {:ok, key}
    else
      {:error, message} -> {:error, message}
      other -> {:error, "Unexpected message #{inspect(other)}"}
    end
  end

  def receive_next(socket, timeout_message) do
    receive do
      {_proto, ^socket, bin} -> Server.decode_pkt(bin)
      other -> {:error, "Unexpected message in receive_next/2 #{inspect(other)}"}
    after
      15_000 -> {:error, timeout_message}
    end
  end

  def reply_first_exchange(sock, method, secrets, channel, nonce, user) do
    {message, signatures} = exchange_first(method, secrets, nonce, user, channel)
    :ok = HandlerHelpers.sock_send(sock, Server.exchange_message(:first, message))
    {:ok, signatures}
  end

  def authenticate_exchange(:password, _secrets, signatures, p) do
    if p == signatures.client,
      do: {:ok, nil},
      else: {:error, "Wrong password"}
  end

  def authenticate_exchange(:auth_query, secrets, signatures, p) do
    client_key = :crypto.exor(Base.decode64!(p), signatures.client)

    if Helpers.hash(client_key) == secrets.().stored_key,
      do: {:ok, client_key},
      else: {:error, "Wrong password"}
  end

  def authenticate_exchange(:auth_query_md5, client_hash, server_hash, salt) do
    if "md5" <> Helpers.md5([server_hash, salt]) == client_hash,
      do: {:ok, nil},
      else: {:error, "Wrong password"}
  end

  @spec update_user_data(map(), map(), String.t(), Supavisor.id(), String.t(), Supavisor.mode()) ::
          map()
  def update_user_data(data, info, user, id, db_name, mode) do
    proxy_type = if info.tenant.require_user, do: :password, else: :auth_query

    auth = %{
      application_name: data.app_name,
      database: info.tenant.db_database,
      host: info.tenant.db_host,
      sni_host: info.tenant.sni_hostname,
      ip_version: info.tenant.ip_version,
      port: info.tenant.db_port,
      user: user,
      password: info.user.db_password,
      require_user: info.tenant.require_user,
      upstream_ssl: info.tenant.upstream_ssl,
      upstream_tls_ca: info.tenant.upstream_tls_ca,
      upstream_verify: info.tenant.upstream_verify
    }

    %{
      data
      | tenant: info.tenant.external_id,
        user: user,
        timeout: info.user.pool_checkout_timeout,
        ps: info.tenant.default_parameter_status,
        proxy_type: proxy_type,
        id: id,
        heartbeat_interval: info.tenant.client_heartbeat_interval * 1000,
        db_name: db_name,
        mode: mode,
        auth: auth
    }
  end

  @spec auth_secrets(map, String.t(), term(), non_neg_integer()) ::
          {:ok, Supavisor.secrets()} | {:error, term()}
  ## password secrets
  def auth_secrets(%{user: user, tenant: %{require_user: true}}, _, _, _) do
    secrets = %{db_user: user.db_user, password: user.db_password, alias: user.db_user_alias}
    {:ok, {:password, fn -> secrets end}}
  end

  ## auth_query secrets
  def auth_secrets(info, db_user, key, ttl) do
    fetch = fn _key ->
      case get_secrets(info, db_user) do
        {:ok, _} = resp -> {:commit, {:cached, resp}, ttl: ttl}
        {:error, _} = resp -> {:ignore, resp}
      end
    end

    case Cachex.fetch(Supavisor.Cache, key, fetch) do
      {:ok, {:cached, value}} -> value
      {:commit, {:cached, value}, _opts} -> value
      {:ignore, resp} -> resp
    end
  end

  @spec get_secrets(map, String.t()) :: {:ok, {:auth_query, fun()}} | {:error, term()}
  def get_secrets(%{user: user, tenant: tenant}, db_user) do
    ssl_opts =
      if tenant.upstream_ssl and tenant.upstream_verify == :peer do
        [
          {:verify, :verify_peer},
          {:cacerts, [Helpers.upstream_cert(tenant.upstream_tls_ca)]},
          {:server_name_indication, String.to_charlist(tenant.db_host)},
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
        parameters: [application_name: "Supavisor auth_query"],
        ssl: tenant.upstream_ssl,
        socket_options: [
          Helpers.ip_version(tenant.ip_version, tenant.db_host)
        ],
        queue_target: 1_000,
        queue_interval: 5_000,
        ssl_opts: ssl_opts || []
      )

    # kill the postgrex connection if the current process exits unexpectedly
    Process.link(conn)

    Logger.debug(
      "ProxyClient: Connected to db #{tenant.db_host} #{tenant.db_port} #{tenant.db_database} #{user.db_user}"
    )

    resp =
      with {:ok, secret} <- Helpers.get_user_secret(conn, tenant.auth_query, db_user) do
        t = if secret.digest == :md5, do: :auth_query_md5, else: :auth_query
        {:ok, {t, fn -> Map.put(secret, :alias, user.db_user_alias) end}}
      end

    GenServer.stop(conn, :normal, 5_000)
    Logger.info("ProxyClient: Get secrets finished")
    resp
  end

  @spec exchange_first(:password | :auth_query, fun(), binary(), binary(), binary()) ::
          {binary(), map()}
  def exchange_first(:password, secret, nonce, user, channel) do
    message = Server.exchange_first_message(nonce)
    server_first_parts = Helpers.parse_server_first(message, nonce)

    {client_final_message, server_proof} =
      Helpers.get_client_final(
        :password,
        secret.().password,
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

  def exchange_first(:auth_query, secret, nonce, user, channel) do
    secret = secret.()
    message = Server.exchange_first_message(nonce, secret.salt)
    server_first_parts = Helpers.parse_server_first(message, nonce)

    sings =
      Helpers.signatures(
        secret.stored_key,
        secret.server_key,
        server_first_parts,
        nonce,
        user,
        channel
      )

    {message, sings}
  end

  @spec timeout_check(atom, non_neg_integer) :: {:timeout, non_neg_integer, atom}
  def timeout_check(key, timeout) do
    {:timeout, timeout, key}
  end

  @spec handle_actions(map) :: [{:timeout, non_neg_integer, atom}]
  defp handle_actions(%{} = data) do
    heartbeat =
      if data.heartbeat_interval > 0,
        do: [{:timeout, data.heartbeat_interval, :heartbeat_check}],
        else: []

    idle =
      if data.idle_timeout > 0, do: [{:timeout, data.idle_timeout, :idle_timeout}], else: []

    idle ++ heartbeat
  end

  @spec app_name(any()) :: String.t()
  def app_name(name) when is_binary(name) do
    suffix = " via Supavisor"
    # https://www.postgresql.org/docs/current/runtime-config-logging.html#GUC-APPLICATION-NAME
    max_len = 64
    suffix_len = 14

    if String.length(name) <= max_len - suffix_len do
      name <> suffix
    else
      truncated_name = String.slice(name, 0, max_len - suffix_len - 3)
      truncated_name <> "..." <> suffix
    end
  end

  def app_name(name) do
    Logger.error("ProxyClient: Invalid application name #{inspect(name)}")
    "via Supavisor"
  end

  @spec maybe_change_log(map()) :: atom() | nil
  def maybe_change_log(%{"payload" => %{"options" => options}}) do
    level = options["log_level"] && String.to_existing_atom(options["log_level"])

    if level in [:debug, :info, :notice, :warning, :error] do
      Helpers.set_log_level(level)
      level
    end
  end

  def maybe_change_log(_), do: :ok

  @spec checkout(pid(), non_neg_integer()) :: {pid(), Supavisor.sock()}
  def checkout(pool, timeout) do
    db_pid = :poolboy.checkout(pool, true, timeout)
    Process.link(db_pid)
    {:ok, db_sock} = DbHandler.change_socket_owner(db_pid, self())
    {db_pid, db_sock}
  end

  @spec db_pid_meta(pid()) :: [{pid(), map()}]
  defp db_pid_meta(pid) do
    rkey = Supavisor.Registry.PoolPids
    fnode = node(pid)

    if fnode == node(),
      do: Registry.lookup(rkey, pid),
      else: :erpc.call(fnode, Registry, :lookup, [rkey, pid], 15_000)
  end
end
