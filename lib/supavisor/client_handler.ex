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
  @cancel_query_msg <<16::32, 1234::16, 5678::16>>

  alias Supavisor.{
    DbHandler,
    HandlerHelpers,
    Helpers,
    Monitoring.Telem,
    Protocol.Client,
    Protocol.Server,
    Tenants
  }

  @impl true
  def start_link(ref, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  @spec db_status(pid(), :ready_for_query | :read_sql_error, binary()) :: :ok
  def db_status(pid, status, bin), do: :gen_statem.cast(pid, {:db_status, status, bin})

  @impl true
  def init(_), do: :ignore

  def init(ref, trans, opts) do
    Process.flag(:trap_exit, true)
    Helpers.set_max_heap_size(90)

    {:ok, sock} = :ranch.handshake(ref)

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
      db_sock: nil,
      auth: %{},
      tenant_availability_zone: nil
    }

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :exchange, data)
  end

  @impl true
  def handle_event(:info, {_proto, _, <<"GET", _::binary>>}, :exchange, data) do
    Logger.debug("ClientHandler: Client is trying to request HTTP")

    HandlerHelpers.sock_send(
      data.sock,
      "HTTP/1.1 204 OK\r\nx-app-version: #{Application.spec(:supavisor, :vsn)}\r\n\r\n"
    )

    {:stop, {:shutdown, :http_request}}
  end

  # cancel request
  def handle_event(:info, {_, _, <<@cancel_query_msg, pid::32, key::32>>}, _, _) do
    Logger.debug("ClientHandler: Got cancel query for #{inspect({pid, key})}")
    :ok = HandlerHelpers.send_cancel_query(pid, key)
    {:stop, {:shutdown, :cancel_query}}
  end

  # send cancel request to db
  def handle_event(:info, :cancel_query, :busy, data) do
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

  def handle_event(:info, {:tcp, _, <<_::64>>}, :exchange, %{sock: sock} = data) do
    Logger.debug("ClientHandler: Client is trying to connect with SSL")

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

  def handle_event(:info, {_, _, bin}, :exchange, data) do
    case Server.decode_startup_packet(bin) do
      {:ok, hello} ->
        Logger.debug("ClientHandler: Client startup message: #{inspect(hello)}")
        {type, {user, tenant_or_alias, db_name}} = HandlerHelpers.parse_user_info(hello.payload)

        not_allowed = ["\"", "\\"]

        if String.contains?(user, not_allowed) or String.contains?(db_name, not_allowed) do
          reason = "Invalid format for user or db_name"
          Logger.error("ClientHandler: #{inspect(reason)}")
          Telem.client_join(:fail, data.id)

          HandlerHelpers.send_error(
            data.sock,
            "XX000",
            "Authentication error, reason: #{inspect(reason)}"
          )

          {:stop, {:shutdown, :invalid_characters}}
        else
          log_level =
            case hello.payload["options"]["log_level"] do
              nil -> nil
              level -> String.to_existing_atom(level)
            end

          Helpers.set_log_level(log_level)

          {:keep_state, %{data | log_level: log_level},
           {:next_event, :internal, {:hello, {type, {user, tenant_or_alias, db_name}}}}}
        end

      {:error, error} ->
        Logger.error("ClientHandler: Client startup message error: #{inspect(error)}")
        Telem.client_join(:fail, data.id)
        {:stop, {:shutdown, :startup_packet_error}}
    end
  end

  def handle_event(
        :internal,
        {:hello, {type, {user, tenant_or_alias, db_name}}},
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
          db_name: db_name
        )

        Registry.register(Supavisor.Registry.TenantClients, id, [])

        {:ok, addr} = HandlerHelpers.addr_from_sock(sock)

        cond do
          info.tenant.enforce_ssl and !data.ssl ->
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
        _,
        %{sock: sock} = data
      ) do
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

  def handle_event(:internal, :subscribe, _, data) do
    Logger.debug("ClientHandler: Subscribe to tenant #{inspect(data.id)}")

    with {:ok, sup} <-
           Supavisor.start_dist(data.id, data.auth_secrets,
             log_level: data.log_level,
             availability_zone: data.tenant_availability_zone
           ),
         true <- if(node(sup) != node() and data.mode == :transaction, do: :proxy, else: true),
         {:ok, opts} <- Supavisor.subscribe(sup, data.id) do
      Process.monitor(opts.workers.manager)
      data = Map.merge(data, opts.workers)
      db_pid = db_checkout(:both, :on_connect, data)
      data = %{data | db_pid: db_pid, idle_timeout: opts.idle_timeout}

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

      :proxy ->
        {:ok, %{port: port, host: host}} = Supavisor.get_pool_ranch(data.id)

        auth =
          Map.merge(data.auth, %{
            port: port,
            host: to_charlist(host),
            ip_version: :inet,
            upstream_ssl: false,
            upstream_tls_ca: nil,
            upstream_verify: nil
          })

        {:keep_state, %{data | auth: auth}, {:next_event, :internal, :connect_db}}

      error ->
        Logger.error("ClientHandler: Subscribe error: #{inspect(error)}")
        {:keep_state_and_data, {:timeout, 1000, :subscribe}}
    end
  end

  def handle_event(:internal, :connect_db, _, data) do
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

  def handle_event(:internal, {:greetings, ps}, _, %{sock: sock} = data) do
    {header, <<pid::32, key::32>> = payload} = Server.backend_key_data()
    msg = [ps, [header, payload], Server.ready_for_query()]
    :ok = HandlerHelpers.listen_cancel_query(pid, key)
    :ok = HandlerHelpers.sock_send(sock, msg)
    Telem.client_connection_time(data.connection_start, data.id)
    {:next_state, :idle, data, handle_actions(data)}
  end

  def handle_event(:timeout, :subscribe, _, _),
    do: {:keep_state_and_data, {:next_event, :internal, :subscribe}}

  def handle_event(:timeout, :wait_ps, _, data) do
    Logger.error(
      "ClientHandler: Wait parameter status timeout, send default #{inspect(data.ps)}}"
    )

    ps = Server.encode_parameter_status(data.ps)
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  def handle_event(:timeout, :idle_terminate, _, data) do
    Logger.warning("ClientHandler: Terminate an idle connection by #{data.idle_timeout} timeout")
    {:stop, {:shutdown, :idle_terminate}}
  end

  def handle_event(:timeout, :heartbeat_check, _, data) do
    Logger.debug("ClientHandler: Send heartbeat to client")
    HandlerHelpers.sock_send(data.sock, Server.application_name())
    {:keep_state_and_data, {:timeout, data.heartbeat_interval, :heartbeat_check}}
  end

  # handle Terminate message
  def handle_event(:info, {proto, _, <<?X, 4::32>>}, :idle, _)
      when proto in @proto do
    Logger.error("ClientHandler: Terminate received from client")
    {:stop, {:shutdown, :terminate_received}}
  end

  # handle Sync message
  def handle_event(:info, {proto, _, <<?S, 4::32>>}, :idle, data)
      when proto in @proto do
    Logger.error("ClientHandler: Receive sync")
    :ok = HandlerHelpers.sock_send(data.sock, Server.ready_for_query())
    {:keep_state_and_data, handle_actions(data)}
  end

  def handle_event(:info, {proto, _, <<?S, 4::32, _::binary>> = msg}, _, data)
      when proto in @proto do
    Logger.error("ClientHandler: Receive sync while not idle")
    :ok = HandlerHelpers.sock_send(elem(data.db_pid, 2), msg)
    :keep_state_and_data
  end

  def handle_event(:info, {proto, _, <<?H, 4::32, _::binary>> = msg}, _, data)
      when proto in @proto do
    Logger.error("ClientHandler: Receive flush while not idle")
    :ok = HandlerHelpers.sock_send(elem(data.db_pid, 2), msg)
    :keep_state_and_data
  end

  # incoming query with a single pool
  def handle_event(:info, {proto, _, bin}, :idle, %{pool: pid} = data)
      when is_binary(bin) and is_pid(pid) do
    Logger.debug("ClientHandler: Receive query #{inspect(bin)}")
    db_pid = db_checkout(:both, :on_query, data)
    handle_prepared_statements(db_pid, bin, data)

    {:next_state, :busy, %{data | db_pid: db_pid, query_start: System.monotonic_time()},
     {:next_event, :internal, {proto, nil, bin}}}
  end

  def handle_event(:info, {proto, _, bin}, _, %{mode: :proxy} = data) do
    {:next_state, :busy, %{data | query_start: System.monotonic_time()},
     {:next_event, :internal, {proto, nil, bin}}}
  end

  # incoming query with read/write pools
  def handle_event(:info, {proto, _, bin}, :idle, data) do
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
     {:next_event, :internal, {proto, nil, bin}}}
  end

  # forward query to db
  def handle_event(_, {proto, _, bin}, :busy, data) when proto in @proto do
    # HandlerHelpers.setopts(data.sock, active: :once)

    Logger.debug("ClientHandler: Forward query to db #{inspect(bin)} #{inspect(data.db_pid)}")

    case HandlerHelpers.sock_send(elem(data.db_pid, 2), bin) do
      :ok ->
        :keep_state_and_data

      error ->
        Logger.error("ClientHandler: error while sending query: #{inspect(error)}")

        HandlerHelpers.sock_send(
          data.sock,
          Server.error_message("XX000", "Error while sending query")
        )

        {:stop, {:shutdown, :send_query_error}}
    end
  end

  def handle_event(:info, {:parameter_status, :updated}, _, _) do
    Logger.warning("ClientHandler: Parameter status is updated")
    {:stop, {:shutdown, :parameter_status_updated}}
  end

  def handle_event(:info, {:parameter_status, ps}, :exchange, _),
    do: {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}

  # client closed connection
  def handle_event(_, {closed, _}, _, data)
      when closed in [:tcp_closed, :ssl_closed] do
    Logger.debug("ClientHandler: #{closed} socket closed for #{inspect(data.tenant)}")
    {:stop, {:shutdown, :socket_closed}}
  end

  # linked DbHandler went down
  def handle_event(:info, {:EXIT, db_pid, reason}, _, data) do
    Logger.error("ClientHandler: DbHandler #{inspect(db_pid)} exited #{inspect(reason)}")
    HandlerHelpers.sock_send(data.sock, Server.error_message("XX000", "DbHandler exited"))
    {:stop, {:shutdown, :db_handler_exit}}
  end

  # pool's manager went down
  def handle_event(:info, {:DOWN, _, _, _, reason}, state, data) do
    Logger.error(
      "ClientHandler: Manager #{inspect(data.manager)} went down #{inspect(reason)} state #{inspect(state)}"
    )

    case {state, reason} do
      {_, :shutdown} -> {:stop, {:shutdown, :manager_shutdown}}
      {:idle, _} -> {:keep_state_and_data, {:next_event, :internal, :subscribe}}
      {:busy, _} -> {:stop, {:shutdown, :manager_down}}
    end
  end

  def handle_event(:info, {:disconnect, reason}, _, _data) do
    Logger.warning("ClientHandler: Disconnected due to #{inspect(reason)}")
    {:stop, {:shutdown, {:disconnect, reason}}}
  end

  # emulate handle_cast
  def handle_event(:cast, {:db_status, status, bin}, :busy, data) do
    case status do
      :ready_for_query ->
        Logger.debug("ClientHandler: Client is ready")

        HandlerHelpers.sock_send(data.sock, bin)
        db_pid = handle_db_pid(data.mode, data.pool, data.db_pid)

        {_, stats} = Telem.network_usage(:client, data.sock, data.id, data.stats)

        Telem.client_query_time(data.query_start, data.id)
        {:next_state, :idle, %{data | db_pid: db_pid, stats: stats}, handle_actions(data)}

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

  def handle_event(type, content, state, data) do
    msg = [
      {"type", type},
      {"content", content},
      {"state", state},
      {"data", data}
    ]

    Logger.debug("ClientHandler: Undefined msg: #{inspect(msg, pretty: true)}")

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
          "Max client connections reached"

        :transaction ->
          "Unable to check out process from the pool due to timeout"
      end

    Logger.error("ClientHandler: #{msg}")
    HandlerHelpers.sock_send(data.sock, Server.error_message("XX000", msg))
    :ok
  end

  def terminate(reason, _state, %{db_pid: {_, pid}}) do
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

  def terminate(reason, _state, _data) do
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
      database: info.tenant.db_database,
      host: to_charlist(info.tenant.db_host),
      sni_host: info.tenant.sni_hostname,
      ip_version: Helpers.ip_version(info.tenant.ip_version, info.tenant.db_host),
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
      if tenant.upstream_ssl and tenant.upstream_verify == "peer" do
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
      "ClientHandler: Connected to db #{tenant.db_host} #{tenant.db_port} #{tenant.db_database} #{user.db_user}"
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

  @spec handle_prepared_statements({pid, pid, Supavisor.sock()}, binary, map) :: :ok | nil
  defp handle_prepared_statements({_, pid, _}, bin, %{mode: :transaction} = data) do
    with {:ok, payload} <- Client.get_payload(bin),
         {:ok, statements} <- Supavisor.PgParser.statements(payload),
         true <- statements in [["PrepareStmt"], ["DeallocateStmt"]] do
      Logger.info("ClientHandler: Handle prepared statement #{inspect(payload)}")

      GenServer.call(data.pool, :get_all_workers)
      |> Enum.each(fn
        {_, ^pid, _, [Supavisor.DbHandler]} ->
          Logger.debug("ClientHandler: Linked DbHandler #{inspect(pid)}")
          nil

        {_, pool_proc, _, [Supavisor.DbHandler]} ->
          Logger.debug(
            "ClientHandler: Sending prepared statement change #{inspect(payload)} to #{inspect(pool_proc)}"
          )

          send(pool_proc, {:handle_ps, payload, bin})
      end)
    else
      error ->
        Logger.debug("ClientHandler: Skip prepared statement #{inspect(error)}")
    end
  end

  defp handle_prepared_statements(_, _, _), do: nil

  @spec handle_actions(map) :: [{:timeout, non_neg_integer, atom}]
  defp handle_actions(%{} = data) do
    heartbeat =
      if data.heartbeat_interval > 0,
        do: [{:timeout, data.heartbeat_interval, :heartbeat_check}],
        else: []

    idle = if data.idle_timeout > 0, do: [{:timeout, data.idle_timeout, :idle_timeout}], else: []

    idle ++ heartbeat
  end
end
