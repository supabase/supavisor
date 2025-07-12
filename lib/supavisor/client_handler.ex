defmodule Supavisor.ClientHandler do
  @moduledoc """
  This module is responsible for handling incoming connections to the Supavisor server. It is
  implemented as a Ranch protocol behavior and a gen_statem behavior. It handles SSL negotiation,
  user authentication, tenant subscription, and dispatching of messages to the appropriate tenant
  supervisor. Each client connection is assigned to a specific tenant supervisor.
  """

  require Logger

  @behaviour :ranch_protocol
  @behaviour :gen_statem
  @proto [:tcp, :ssl]
  @switch_active_count Application.compile_env(:supavisor, :switch_active_count)
  @subscribe_retries Application.compile_env(:supavisor, :subscribe_retries)
  @timeout_subscribe 500
  @clients_registry Supavisor.Registry.TenantClients
  @proxy_clients_registry Supavisor.Registry.TenantProxyClients

  alias Supavisor.{
    DbHandler,
    HandlerHelpers,
    Helpers,
    Monitoring.Telem,
    Protocol,
    Protocol.Client,
    Protocol.PreparedStatements,
    Tenants
  }

  require Supavisor.Protocol.Server, as: Server

  @impl true
  def start_link(ref, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  @spec db_status(pid(), :ready_for_query | :read_sql_error) :: :ok
  def db_status(pid, status), do: :gen_statem.cast(pid, {:db_status, status})

  @impl true
  def init(_), do: :ignore

  def init(ref, trans, opts) do
    Process.flag(:trap_exit, true)
    Helpers.set_max_heap_size(90)

    {:ok, sock} = :ranch.handshake(ref)
    peer_ip = Helpers.peer_ip(sock)
    local = opts[:local] || false

    Logger.metadata(
      peer_ip: peer_ip,
      local: local,
      state: :init
    )

    :ok =
      trans.setopts(sock,
        # mode: :binary,
        # packet: :raw,
        # recbuf: 8192,
        # sndbuf: 8192,
        # # backlog: 2048,
        # send_timeout: 120,
        # keepalive: true,
        # nodelay: true,
        # nopush: true,
        active: true
      )

    Logger.debug("ClientHandler is: #{inspect(self())}")

    data = %{
      id: nil,
      sock: {:gen_tcp, sock},
      trans: trans,
      db_pid: nil,
      tenant: nil,
      user: nil,
      pool: nil,
      manager: nil,
      query_start: nil,
      timeout: nil,
      ps: nil,
      ssl: false,
      auth_secrets: nil,
      proxy_type: nil,
      mode: opts.mode,
      stats: %{},
      idle_timeout: 0,
      db_name: nil,
      last_query: nil,
      heartbeat_interval: 0,
      connection_start: System.monotonic_time(),
      log_level: nil,
      auth: %{},
      tenant_availability_zone: nil,
      local: local,
      active_count: 0,
      peer_ip: peer_ip,
      app_name: nil,
      subscribe_retries: 0,
      prepared_statements: %{},
      pending: ""
    }

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :exchange, data)
  end

  @impl true
  def handle_event(:info, {_proto, _, <<"GET", _::binary>>}, :exchange, data) do
    Logger.metadata(state: :exchange)
    Logger.debug("ClientHandler: Client is trying to request HTTP")

    HandlerHelpers.sock_send(
      data.sock,
      "HTTP/1.1 204 OK\r\nx-app-version: #{Application.spec(:supavisor, :vsn)}\r\n\r\n"
    )

    {:stop, {:shutdown, :http_request}}
  end

  # cancel request
  def handle_event(:info, {_, _, Server.cancel_message(pid, key)}, state, _) do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: Got cancel query for #{inspect({pid, key})}")
    :ok = HandlerHelpers.send_cancel_query(pid, key)
    {:stop, {:shutdown, :cancel_query}}
  end

  # send cancel request to db
  def handle_event(:info, :cancel_query, :busy, data) do
    Logger.metadata(state: :busy)
    key = {data.tenant, data.db_pid}
    Logger.debug("ClientHandler: Cancel query for #{inspect(key)}")
    {_pool, db_pid, _db_sock} = data.db_pid

    case db_pid_meta(key) do
      [{^db_pid, meta}] ->
        :ok = HandlerHelpers.cancel_query(meta.host, meta.port, meta.ip_ver, meta.pid, meta.key)

      error ->
        Logger.error(
          "ClientHandler: Received cancel but no proc was found #{inspect(key)} #{inspect(error)}"
        )
    end

    :keep_state_and_data
  end

  def handle_event(:info, :cancel_query, :idle, _data) do
    :keep_state_and_data
  end

  def handle_event(
        :info,
        {:tcp, _, Server.ssl_request_message()},
        :exchange,
        %{sock: sock} = data
      ) do
    Logger.metadata(state: :exchange)
    Logger.debug("ClientHandler: Client is trying to connect with SSL")

    downstream_cert = Helpers.downstream_cert()
    downstream_key = Helpers.downstream_key()

    # SSL negotiation, S/N/Error
    if !!downstream_cert and !!downstream_key do
      :ok = HandlerHelpers.setopts(sock, active: false)
      :ok = HandlerHelpers.sock_send(sock, "S")

      opts = [
        verify: :verify_none,
        certfile: downstream_cert,
        keyfile: downstream_key
      ]

      case :ssl.handshake(elem(sock, 1), opts) do
        {:ok, ssl_sock} ->
          socket = {:ssl, ssl_sock}
          :ok = HandlerHelpers.setopts(socket, active: true)
          {:keep_state, %{data | sock: socket, ssl: true}}

        error ->
          Logger.error("ClientHandler: SSL handshake error: #{inspect(error)}")
          Telem.client_join(:fail, data.id)
          {:stop, {:shutdown, :ssl_handshake_error}}
      end
    else
      Logger.error(
        "ClientHandler: User requested SSL connection but no downstream cert/key found"
      )

      :ok = HandlerHelpers.sock_send(data.sock, "N")
      :keep_state_and_data
    end
  end

  def handle_event(:info, {_, _, bin}, :exchange, _) when byte_size(bin) > 1024 do
    Logger.metadata(state: :exchange)
    Logger.error("ClientHandler: Startup packet too large #{byte_size(bin)}")
    {:stop, {:shutdown, :startup_packet_too_large}}
  end

  def handle_event(:info, {_, _, bin}, :exchange, data) do
    Logger.metadata(state: :exchange)

    case Server.decode_startup_packet(bin) do
      {:ok, hello} ->
        Logger.debug("ClientHandler: Client startup message: #{inspect(hello)}")
        {type, {user, tenant_or_alias, db_name}} = HandlerHelpers.parse_user_info(hello.payload)

        if Helpers.validate_name(user) and Helpers.validate_name(db_name) do
          log_level = maybe_change_log(hello)
          search_path = hello.payload["options"]["--search_path"]
          event = {:hello, {type, {user, tenant_or_alias, db_name, search_path}}}
          app_name = app_name(hello.payload["application_name"])

          {:keep_state, %{data | log_level: log_level, app_name: app_name},
           {:next_event, :internal, event}}
        else
          reason = "Invalid format for user or db_name"

          Logger.error("ClientHandler: #{inspect(reason)} #{inspect({user, db_name})}")

          Telem.client_join(:fail, tenant_or_alias)

          HandlerHelpers.send_error(
            data.sock,
            "XX000",
            "Authentication error, reason: #{inspect(reason)}"
          )

          {:stop, {:shutdown, :invalid_format}}
        end

      {:error, error} ->
        Logger.error("ClientHandler: Client startup message error: #{inspect(error)}")

        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :startup_packet_error}}
    end
  end

  def handle_event(
        :internal,
        {:hello, {type, {user, tenant_or_alias, db_name, search_path}}},
        :exchange,
        %{sock: sock} = data
      ) do
    Logger.metadata(state: :exchange)
    sni_hostname = HandlerHelpers.try_get_sni(sock)

    case Tenants.get_user_cache(type, user, tenant_or_alias, sni_hostname) do
      {:ok, info} ->
        db_name = db_name || info.tenant.db_database

        id =
          Supavisor.id(
            {type, tenant_or_alias},
            user,
            data.mode,
            info.user.mode_type,
            db_name,
            search_path
          )

        mode = Supavisor.mode(id)

        Logger.metadata(
          project: tenant_or_alias,
          user: user,
          mode: mode,
          type: type,
          db_name: db_name,
          app_name: data.app_name
        )

        {:ok, addr} = HandlerHelpers.addr_from_sock(sock)

        cond do
          !data.local and info.tenant.enforce_ssl and !data.ssl ->
            Logger.error(
              "ClientHandler: Tenant is not allowed to connect without SSL, user #{user}"
            )

            :ok = HandlerHelpers.send_error(sock, "XX000", "SSL connection is required")
            Telem.client_join(:fail, id)
            {:stop, {:shutdown, :ssl_required}}

          HandlerHelpers.filter_cidrs(info.tenant.allow_list, addr) == [] ->
            message = "Address not in tenant allow_list: " <> inspect(addr)
            Logger.error("ClientHandler: #{message}")
            :ok = HandlerHelpers.send_error(sock, "XX000", message)

            Telem.client_join(:fail, id)
            {:stop, {:shutdown, :address_not_allowed}}

          true ->
            new_data = update_user_data(data, info, user, id, db_name, mode)

            key = {:secrets, tenant_or_alias, user}

            case auth_secrets(info, user, key, :timer.hours(24)) do
              {:ok, auth_secrets} ->
                Logger.debug("ClientHandler: Authentication method: #{inspect(auth_secrets)}")

                {:keep_state, new_data, {:next_event, :internal, {:handle, auth_secrets, info}}}

              {:error, reason} ->
                Logger.error(
                  "ClientHandler: Authentication auth_secrets error: #{inspect(reason)}"
                )

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
          "ClientHandler: User not found: #{inspect(reason)} #{inspect({type, user, tenant_or_alias})}"
        )

        :ok = HandlerHelpers.send_error(sock, "XX000", "Tenant or user not found")
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :user_not_found}}
    end
  end

  def handle_event(
        :internal,
        {:handle, {method, secrets}, info},
        state,
        %{sock: sock} = data
      ) do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: Handle exchange, auth method: #{inspect(method)}")

    case handle_exchange(sock, {method, secrets}) do
      {:error, reason} ->
        Logger.error(
          "ClientHandler: Exchange error: #{inspect(reason)} when method #{inspect(method)}"
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
                Logger.warning("ClientHandler: Update secrets and terminate pool")

                Cachex.update(
                  Supavisor.Cache,
                  {:secrets, data.tenant, data.user},
                  {:cached, value}
                )

                Supavisor.stop(data.id)
              else
                Logger.debug("ClientHandler: Cache the same #{inspect(key)}")
              end

            other ->
              Logger.error("ClientHandler: Auth secrets check error: #{inspect(other)}")
          end
        else
          Logger.debug("ClientHandler: Cache hit for #{inspect(key)}")
        end

        HandlerHelpers.sock_send(sock, msg)
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :exchange_error}}

      {:ok, client_key} ->
        secrets =
          if client_key,
            do: fn -> Map.put(secrets.(), :client_key, client_key) end,
            else: secrets

        Logger.debug("ClientHandler: Exchange success")
        :ok = HandlerHelpers.sock_send(sock, Server.authentication_ok())
        Telem.client_join(:ok, data.id)

        auth = Map.merge(data.auth, %{secrets: secrets, method: method})

        conn_type =
          if data.mode == :proxy,
            do: :connect_db,
            else: :subscribe

        {:keep_state, %{data | auth_secrets: {method, secrets}, auth: auth},
         {:next_event, :internal, conn_type}}
    end
  end

  def handle_event(:internal, :subscribe, state, data) do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: Subscribe to tenant #{inspect(data.id)}")

    with {:ok, sup} <-
           Supavisor.start_dist(data.id, data.auth_secrets,
             log_level: data.log_level,
             availability_zone: data.tenant_availability_zone
           ),
         true <-
           if(node(sup) != node() and data.mode in [:transaction, :session],
             do: :proxy,
             else: true
           ),
         {:ok, opts} <- Supavisor.subscribe(sup, data.id) do
      manager_ref = Process.monitor(opts.workers.manager)

      data = Map.merge(data, opts.workers)
      db_pid = db_checkout(:both, :on_connect, data)
      data = %{data | manager: manager_ref, db_pid: db_pid, idle_timeout: opts.idle_timeout}

      Registry.register(@clients_registry, data.id, started_at: System.monotonic_time())

      next =
        if opts.ps == [],
          do: {:timeout, 10_000, :wait_ps},
          else: {:next_event, :internal, {:greetings, opts.ps}}

      {:keep_state, data, next}
    else
      {:error, :max_clients_reached} ->
        msg = "Max client connections reached"
        Logger.error("ClientHandler: #{msg}")
        :ok = HandlerHelpers.send_error(data.sock, "XX000", msg)
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :max_clients_reached}}

      {:error, :max_pools_reached} ->
        msg = "Max pools count reached"
        Logger.error("ClientHandler: #{msg}")
        :ok = HandlerHelpers.send_error(data.sock, "XX000", msg)
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :max_pools_reached}}

      :proxy ->
        case Supavisor.get_pool_ranch(data.id) do
          {:ok, %{port: port, host: host}} ->
            auth =
              Map.merge(data.auth, %{
                port: port,
                host: to_charlist(host),
                ip_version: :inet,
                upstream_ssl: false,
                upstream_tls_ca: nil,
                upstream_verify: nil
              })

            Logger.metadata(proxy: true)
            Registry.register(@proxy_clients_registry, data.id, [])

            {:keep_state, %{data | auth: auth}, {:next_event, :internal, :connect_db}}

          other ->
            Logger.error("ClientHandler: Subscribe proxy error: #{inspect(other)}")
            timeout_subscribe_or_terminate(data)
        end

      error ->
        Logger.error("ClientHandler: Subscribe error: #{inspect(error)}")
        timeout_subscribe_or_terminate(data)
    end
  end

  def handle_event(:internal, :connect_db, state, data) do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: Trying to connect to DB")

    args = %{
      id: data.id,
      auth: data.auth,
      user: data.user,
      tenant: {:single, data.tenant},
      replica_type: :write,
      mode: :proxy,
      proxy: true,
      log_level: data.log_level,
      caller: self(),
      client_sock: data.sock
    }

    {:ok, db_pid} = DbHandler.start_link(args)
    db_sock = :gen_statem.call(db_pid, {:checkout, data.sock, self()})
    {:keep_state, %{data | db_pid: {nil, db_pid, db_sock}, mode: :proxy}}
  end

  def handle_event(:internal, {:greetings, ps}, state, %{sock: sock} = data) do
    Logger.metadata(state: state)
    {header, <<pid::32, key::32>> = payload} = Server.backend_key_data()
    msg = [ps, [header, payload], Server.ready_for_query()]
    :ok = HandlerHelpers.listen_cancel_query(pid, key)
    :ok = HandlerHelpers.sock_send(sock, msg)
    Telem.client_connection_time(data.connection_start, data.id)
    {:next_state, :idle, data, handle_actions(data)}
  end

  def handle_event(:timeout, :subscribe, state, _) do
    Logger.metadata(state: state)
    {:keep_state_and_data, {:next_event, :internal, :subscribe}}
  end

  def handle_event(:timeout, :wait_ps, state, data) do
    Logger.metadata(state: state)

    Logger.error(
      "ClientHandler: Wait parameter status timeout, send default #{inspect(data.ps)}}"
    )

    ps = Server.encode_parameter_status(data.ps)
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  def handle_event(:timeout, :idle_terminate, state, data) do
    Logger.metadata(state: state)
    Logger.warning("ClientHandler: Terminate an idle connection by #{data.idle_timeout} timeout")
    {:stop, {:shutdown, :idle_terminate}}
  end

  def handle_event(:timeout, :heartbeat_check, state, data) do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: Send heartbeat to client")
    HandlerHelpers.sock_send(data.sock, Server.application_name())
    {:keep_state_and_data, {:timeout, data.heartbeat_interval, :heartbeat_check}}
  end

  def handle_event(kind, {proto, socket, msg}, state, data) when proto in @proto do
    Logger.metadata(state: state)

    with {:next_state, next_state, new_data, actions} <- handle_data(kind, msg, state, data) do
      new_actions =
        actions
        |> List.wrap()
        |> Enum.map(fn
          {:next_event, type, bin_or_pkts} when is_binary(bin_or_pkts) or is_list(bin_or_pkts) ->
            {:next_event, type, {proto, socket, bin_or_pkts}}
          other ->
            other
        end)

      {:next_state, next_state, new_data, new_actions}
    end
  end

  def handle_event(:info, {:parameter_status, ps}, :exchange, _) do
    Logger.metadata(state: :exchange)
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  def handle_event(:info, {:ssl_error, sock, reason}, _, %{sock: {_, sock}}) do
    Logger.metadata(state: :exchange)
    Logger.error("ClientHandler: TLS error #{inspect(reason)}")
    :keep_state_and_data
  end

  # client closed connection
  def handle_event(_, {closed, _}, state, data)
      when closed in [:tcp_closed, :ssl_closed] do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: #{closed} socket closed for #{inspect(data.tenant)}")
    {:stop, {:shutdown, :socket_closed}}
  end

  # linked DbHandler went down
  def handle_event(:info, {:EXIT, db_pid, reason}, state, data) do
    Logger.metadata(state: state)
    Logger.error("ClientHandler: DbHandler #{inspect(db_pid)} exited #{inspect(reason)}")
    HandlerHelpers.sock_send(data.sock, Server.error_message("XX000", "DbHandler exited"))
    {:stop, {:shutdown, :db_handler_exit}}
  end

  # pool's manager went down
  def handle_event(:info, {:DOWN, ref, _, _, reason}, state, %{manager: ref} = data) do
    Logger.metadata(state: state)

    Logger.error(
      "ClientHandler: Manager #{inspect(data.manager)} went down #{inspect(reason)} state #{inspect(state)}"
    )

    case {state, reason} do
      {_, :shutdown} -> {:stop, {:shutdown, :manager_shutdown}}
      {:idle, _} -> {:keep_state_and_data, {:next_event, :internal, :subscribe}}
      {:busy, _} -> {:stop, {:shutdown, :manager_down}}
    end
  end

  def handle_event(:info, {:disconnect, reason}, state, _data) do
    Logger.metadata(state: state)
    Logger.warning("ClientHandler: Disconnected due to #{inspect(reason)}")
    {:stop, {:shutdown, {:disconnect, reason}}}
  end

  # emulate handle_cast
  def handle_event(:cast, {:db_status, status}, :busy, data) do
    Logger.metadata(state: :busy)

    case status do
      :ready_for_query ->
        Logger.debug("ClientHandler: Client is ready")

        db_pid = handle_db_pid(data.mode, data.pool, data.db_pid)

        {_, stats} =
          if data.local,
            do: {nil, data.stats},
            else: Telem.network_usage(:client, data.sock, data.id, data.stats)

        Telem.client_query_time(data.query_start, data.id)

        {:next_state, :idle,
         %{data | db_pid: db_pid, stats: stats, active_count: reset_active_count(data)},
         handle_actions(data)}

      :read_sql_error ->
        Logger.error(
          "ClientHandler: read only sql transaction, rerunning the query to write pool"
        )

        # release the read pool
        _ = handle_db_pid(data.mode, data.pool, data.db_pid)

        ts = System.monotonic_time()
        db_pid = db_checkout(:write, :on_query, data)

        {:keep_state, %{data | db_pid: db_pid, query_start: ts},
         {:next_event, :internal, {:tcp, nil, data.last_query}}}
    end
  end

  def handle_event(:info, {sock_error, _sock, msg}, state, _data)
      when sock_error in [:tcp_error, :ssl_error] do
    Logger.metadata(state: state)
    Logger.error("ClientHandler: Socket error: #{inspect(msg)}")

    {:stop, {:shutdown, {:socket_error, msg}}}
  end

  def handle_event(type, content, state, _data) do
    Logger.metadata(state: state)

    msg = [
      {"type", type},
      {"content", content}
    ]

    Logger.error("ClientHandler: Undefined msg: #{inspect(msg, pretty: true)}")

    :keep_state_and_data
  end

  @impl true
  def terminate(
        {:timeout, {_, _, [_, {:checkout, _, _}, _]}},
        state,
        data
      ) do
    Logger.metadata(state: state)

    msg =
      case data.mode do
        :session ->
          "MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size"

        :transaction ->
          "Unable to check out process from the pool due to timeout"
      end

    Logger.error("ClientHandler: #{msg}")
    HandlerHelpers.sock_send(data.sock, Server.error_message("XX000", msg))
    :ok
  end

  def terminate(reason, state, %{db_pid: {_, pid, _}}) do
    Logger.metadata(state: state)

    db_info =
      with {:ok, {state, mode} = resp} <- DbHandler.get_state_and_mode(pid) do
        if state == :busy or mode == :session, do: DbHandler.stop(pid)
        resp
      end

    Logger.debug(
      "ClientHandler: socket closed with reason #{inspect(reason)}, DbHandler #{inspect({pid, db_info})}"
    )

    :ok
  end

  def terminate(reason, state, _data) do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: socket closed with reason #{inspect(reason)}")
    :ok
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

  defp receive_next(socket, timeout_message) do
    receive do
      {_proto, ^socket, bin} ->
        Server.decode_pkt(bin)

      other ->
        {:error, "Unexpected message in receive_next/2 #{inspect(other)}"}
    after
      15_000 -> {:error, timeout_message}
    end
  end

  defp reply_first_exchange(sock, method, secrets, channel, nonce, user) do
    {message, signatures} = exchange_first(method, secrets, nonce, user, channel)
    :ok = HandlerHelpers.sock_send(sock, Server.exchange_message(:first, message))
    {:ok, signatures}
  end

  defp authenticate_exchange(:password, _secrets, signatures, p) do
    if p == signatures.client,
      do: {:ok, nil},
      else: {:error, "Wrong password"}
  end

  defp authenticate_exchange(:auth_query, secrets, signatures, p) do
    client_key = :crypto.exor(Base.decode64!(p), signatures.client)

    if Helpers.hash(client_key) == secrets.().stored_key do
      {:ok, client_key}
    else
      {:error, "Wrong password"}
    end
  end

  defp authenticate_exchange(:auth_query_md5, client_hash, server_hash, salt) do
    if "md5" <> Helpers.md5([server_hash, salt]) == client_hash,
      do: {:ok, nil},
      else: {:error, "Wrong password"}
  end

  @spec db_checkout(:write | :read | :both, :on_connect | :on_query, map) ::
          {pid, pid, Supavisor.sock()} | nil
  defp db_checkout(_, _, %{mode: mode, db_pid: {pool, db_pid, db_sock}})
       when is_pid(db_pid) and mode in [:session, :proxy] do
    {pool, db_pid, db_sock}
  end

  defp db_checkout(_, :on_connect, %{mode: :transaction}), do: nil

  defp db_checkout(query_type, _, data) when query_type in [:write, :read] do
    pool =
      data.pool[query_type]
      |> Enum.random()

    {time, db_pid} = :timer.tc(:poolboy, :checkout, [pool, true, data.timeout])
    Process.link(db_pid)
    same_box = if node(db_pid) == node(), do: :local, else: :remote
    Telem.pool_checkout_time(time, data.id, same_box)
    {pool, db_pid}
  end

  defp db_checkout(_, _, data) do
    start = System.monotonic_time(:microsecond)
    db_pid = :poolboy.checkout(data.pool, true, data.timeout)
    Process.link(db_pid)
    db_sock = DbHandler.checkout(db_pid, data.sock, self())
    same_box = if node(db_pid) == node(), do: :local, else: :remote
    Telem.pool_checkout_time(System.monotonic_time(:microsecond) - start, data.id, same_box)
    {data.pool, db_pid, db_sock}
  end

  @spec handle_db_pid(:transaction, pid(), pid() | nil) :: nil
  @spec handle_db_pid(:session, pid(), pid()) :: pid()
  @spec handle_db_pid(:proxy, pid(), pid()) :: pid()
  defp handle_db_pid(:transaction, _pool, nil), do: nil

  defp handle_db_pid(:transaction, pool, {_, db_pid, _}) do
    Process.unlink(db_pid)
    :poolboy.checkin(pool, db_pid)
    nil
  end

  defp handle_db_pid(:session, _, db_pid), do: db_pid
  defp handle_db_pid(:proxy, _, db_pid), do: db_pid

  defp update_user_data(data, info, user, id, db_name, mode) do
    proxy_type =
      if info.tenant.require_user,
        do: :password,
        else: :auth_query

    auth = %{
      application_name: data[:app_name] || "Supavisor",
      database: db_name,
      host: to_charlist(info.tenant.db_host),
      sni_hostname:
        if(info.tenant.sni_hostname != nil, do: to_charlist(info.tenant.sni_hostname)),
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
        auth: auth,
        tenant_availability_zone: info.tenant.availability_zone
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
          verify: :verify_peer,
          cacerts: [Helpers.upstream_cert(tenant.upstream_tls_ca)],
          server_name_indication: String.to_charlist(tenant.db_host),
          customize_hostname_check: [{:match_fun, fn _, _ -> true end}]
        ]
      else
        [
          verify: :verify_none
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
        ssl_opts: ssl_opts
      )

    try do
      Logger.debug(
        "ClientHandler: Connected to db #{tenant.db_host} #{tenant.db_port} #{tenant.db_database} #{user.db_user}"
      )

      resp =
        with {:ok, secret} <- Helpers.get_user_secret(conn, tenant.auth_query, db_user) do
          t = if secret.digest == :md5, do: :auth_query_md5, else: :auth_query
          {:ok, {t, fn -> Map.put(secret, :alias, user.db_user_alias) end}}
        end

      Logger.info("ClientHandler: Get secrets finished")
      resp
    rescue
      exception ->
        Logger.error("ClientHandler: Couldn't fetch user secrets from #{tenant.db_host}")
        reraise exception, __STACKTRACE__
    after
      GenServer.stop(conn, :normal, 5_000)
    end
  end

  @spec exchange_first(:password | :auth_query, fun(), binary(), binary(), binary()) ::
          {binary(), map()}
  defp exchange_first(:password, secret, nonce, user, channel) do
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

  defp exchange_first(:auth_query, secret, nonce, user, channel) do
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

  @spec try_get_sni(Supavisor.sock()) :: String.t() | nil
  def try_get_sni({:ssl, sock}) do
    case :ssl.connection_information(sock, [:sni_hostname]) do
      {:ok, [sni_hostname: sni]} -> List.to_string(sni)
      _ -> nil
    end
  end

  def try_get_sni(_), do: nil

  defp db_pid_meta({_, {_, pid, _}} = _key) do
    rkey = Supavisor.Registry.PoolPids
    fnode = node(pid)

    if fnode == node() do
      Registry.lookup(rkey, pid)
    else
      :erpc.call(fnode, Registry, :lookup, [rkey, pid], 15_000)
    end
  end

  @spec handle_data(kind :: atom(), data :: binary(), state, data) ::
          :gen_statem.event_handler_result(data)
        when state: atom() | term(),
             data: term()

  # handle Terminate message
  defp handle_data(:info, <<?X, 4::32>>, :idle, %{local: true}) do
    Logger.info("ClientHandler: Terminate received from proxy client")
    :keep_state_and_data
  end

  defp handle_data(:info, <<?X, 4::32>>, :idle, _data) do
    Logger.info("ClientHandler: Terminate received from client")
    {:stop, {:shutdown, :terminate_received}}
  end

  defp handle_data(:info, <<?S, 4::32>> <> _ = msg, :idle, data) do
    Logger.debug("ClientHandler: Receive sync")

    # db_pid can be nil in transaction mode, so we will send ready_for_query
    # without checking out a direct connection. If there is a linked db_pid,
    # we will forward the message to it
    if data.db_pid != nil,
      do: :ok = sock_send_binary_maybe_active_once(msg, data),
      else: :ok = HandlerHelpers.sock_send(data.sock, Server.ready_for_query())

    {:keep_state, %{data | active_count: reset_active_count(data)}, handle_actions(data)}
  end

  defp handle_data(:info, <<?S, 4::32, _::binary>> = msg, _, data) do
    Logger.debug("ClientHandler: Receive sync while not idle")
    :ok = sock_send_binary_maybe_active_once(msg, data)
    {:keep_state, %{data | active_count: reset_active_count(data)}, handle_actions(data)}
  end

  # handle Flush message
  defp handle_data(:info, <<?H, 4::32, _::binary>> = msg, _, data) do
    Logger.debug("ClientHandler: Receive flush while not idle")
    :ok = sock_send_binary_maybe_active_once(msg, data)
    {:keep_state, %{data | active_count: reset_active_count(data)}, handle_actions(data)}
  end

  # incoming query with a single pool
  defp handle_data(:info, bin, :idle, %{pool: pid} = data) when is_pid(pid) do
    Logger.debug("ClientHandler: Receive query #{inspect(bin)}")
    db_pid = db_checkout(:both, :on_query, data)

    {:next_state, :busy,
     %{
       data
       | db_pid: db_pid,
         query_start: System.monotonic_time()
     }, {:next_event, :internal, bin}}
  end

  defp handle_data(:info, bin, _, %{mode: :proxy} = data) do
    {:next_state, :busy, %{data | query_start: System.monotonic_time()},
     {:next_event, :internal, bin}}
  end

  # incoming query with read/write pools
  defp handle_data(:info, bin, :idle, data) do
    query_type =
      with {:ok, payload} <- Client.get_payload(bin),
           {:ok, statements} <- Supavisor.PgParser.statements(payload) do
        Logger.debug(
          "ClientHandler: Receive payload #{inspect(payload, pretty: true)} statements #{inspect(statements)}"
        )

        case statements do
          # naive check for read only queries
          ["SelectStmt"] -> :read
          _ -> :write
        end
      else
        other ->
          Logger.error("ClientHandler: Receive query error: #{inspect(other)}")
          :write
      end

    ts = System.monotonic_time()
    db_pid = db_checkout(query_type, :on_query, data)

    {:next_state, :busy, %{data | db_pid: db_pid, query_start: ts, last_query: bin},
     {:next_event, :internal, bin}}
  end

  # forward query to db
  defp handle_data(_, data_to_send, :busy, data) do
    Logger.debug(
      "ClientHandler: Forward query to db #{inspect(data_to_send)} #{inspect(data.db_pid)}"
    )

    case handle_client_pkts(<<data.pending::binary, data_to_send::binary>>, data) do
      {:ok, bin_or_pkts, prepared_statements, rest} ->
        case sock_send_maybe_active_once(bin_or_pkts, data) do
          :ok ->
            {:keep_state,
             %{
               data
               | prepared_statements: prepared_statements,
                 pending: rest,
                 active_count: data.active_count + 1
             }}

          error ->
            Logger.error("ClientHandler: error while sending query: #{inspect(error)}")

            HandlerHelpers.sock_send(
              data.sock,
              Server.error_message("XX000", "Error while sending query")
            )

            {:stop, {:shutdown, :send_query_error}}
        end

      {:error, :max_prepared_statements} ->
        message_text =
          "Max prepared statements limit reached. Limit: #{PreparedStatements.client_limit()} per connection"

        HandlerHelpers.sock_send(
          data.sock,
          Server.error_message("XX000", message_text)
        )

        {:stop, {:shutdown, :max_prepared_statements}}

      {:error, :prepared_statement_on_simple_query} ->
        message_text = "Supavisor only supports PREPARE/EXECUTE using the Extended Query Protocol"

        # Because this is simple query protocol, we need to send ready_for_query after the error,
        HandlerHelpers.sock_send(
          data.sock,
          [Server.error_message("XX000", message_text), Server.ready_for_query()]
        )

        {:stop, {:shutdown, :prepared_statement_on_simple_query}}
    end
  end

  @spec handle_client_pkts(binary, map) ::
          {:ok, [PreparedStatements.handled_pkt()] | binary, map, binary}
          | {:error, :max_prepared_statements}
          | {:error, :prepared_statement_on_simple_query}
  defp handle_client_pkts(
         bin,
         %{mode: :transaction} = data
       ) do
    stmts = data.prepared_statements
    {pkts, rest} = Protocol.split_pkts(bin)

    pkts
    |> Enum.reduce_while({:ok, stmts, []}, fn pkt, {:ok, stmts, pkts} ->
      case PreparedStatements.handle_pkt(stmts, pkt) do
        {:ok, stmts, pkt} ->
          {:cont, {:ok, stmts, [pkt | pkts]}}

        error ->
          {:halt, error}
      end
    end)
    |> case do
      {:ok, stmts, pkts} ->
        {:ok, Enum.reverse(pkts), stmts, rest}

      error ->
        error
    end
  end

  defp handle_client_pkts(bin, data), do: {:ok, bin, data.prepared_statements, data.pending}

  @spec handle_actions(map) :: [{:timeout, non_neg_integer, atom}]
  defp handle_actions(%{} = data) do
    heartbeat =
      if data.heartbeat_interval > 0,
        do: [{:timeout, data.heartbeat_interval, :heartbeat_check}],
        else: []

    idle = if data.idle_timeout > 0, do: [{:timeout, data.idle_timeout, :idle_timeout}], else: []

    idle ++ heartbeat
  end

  @spec app_name(any()) :: String.t()
  def app_name(name) when is_binary(name), do: name

  def app_name(nil), do: "Supavisor"

  def app_name(name) do
    Logger.debug("ClientHandler: Invalid application name #{inspect(name)}")
    "Supavisor"
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

  defp sock_send_maybe_active_once(bin, data) when is_binary(bin) do
    sock_send_binary_maybe_active_once(bin, data)
  end

  defp sock_send_maybe_active_once(pkts, data) when is_list(pkts) do
    sock_send_pkts_maybe_active_once(pkts, data)
  end

  @spec sock_send_binary_maybe_active_once(binary(), map()) :: :ok | {:error, term()}
  defp sock_send_binary_maybe_active_once(bin, data) when is_binary(bin) do
    Logger.debug("ClientHandler: Send maybe active once")
    active_count = data.active_count

    if active_count > @switch_active_count do
      Logger.debug("ClientHandler: Activate socket #{inspect(active_count)}")
      HandlerHelpers.active_once(data.sock)
    end

    HandlerHelpers.sock_send(elem(data.db_pid, 2), bin)
  end

  # Chunking to ensure we send bigger packets
  @spec sock_send_pkts_maybe_active_once([PreparedStatements.handled_pkt()], map()) ::
          :ok | {:error, term()}
  defp sock_send_pkts_maybe_active_once(pkts, data) do
    {_pool, db_handler, db_sock} = data.db_pid
    active_count = data.active_count

    if active_count > @switch_active_count do
      Logger.debug("ClientHandler: Activate socket #{inspect(active_count)}")
      HandlerHelpers.active_once(data.sock)
    end

    pkts
    |> Enum.chunk_by(&is_tuple/1)
    |> Enum.reduce_while(:ok, fn chunk, _acc ->
      case chunk do
        [t | _] = prepared_pkts when is_tuple(t) ->
          Supavisor.DbHandler.handle_prepared_statement_pkts(db_handler, prepared_pkts)

        bins ->
          HandlerHelpers.sock_send(db_sock, bins)
      end
      |> case do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  @spec timeout_subscribe_or_terminate(map()) :: :gen_statem.handle_event_result()
  def timeout_subscribe_or_terminate(%{subscribe_retries: subscribe_retries} = data) do
    if subscribe_retries < @subscribe_retries do
      Logger.warning("ClientHandler: Retry subscribe #{inspect(subscribe_retries)}")

      {:keep_state, %{data | subscribe_retries: subscribe_retries + 1},
       {:timeout, @timeout_subscribe, :subscribe}}
    else
      Logger.error("ClientHandler: Terminate after retries")
      {:stop, {:shutdown, :subscribe_retries}}
    end
  end

  @spec reset_active_count(map()) :: 0
  def reset_active_count(data) do
    HandlerHelpers.activate(data.sock)
    0
  end
end
