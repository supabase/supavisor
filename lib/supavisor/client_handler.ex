defmodule Supavisor.ClientHandler do
  @moduledoc """
  This module is responsible for handling incoming connections to the Supavisor server.

  It implements the Ranch protocol behavior and a gen_statem behavior. It handles SSL negotiation,
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
    Protocol.Debug,
    Tenants
  }

  alias Supavisor.ClientHandler.{
    Auth,
    Cancel,
    Data,
    Error,
    ProtocolHelpers,
    Proxy
  }

  require Supavisor.Protocol.Server, as: Server
  require Supavisor.Protocol.PreparedStatements, as: PreparedStatements

  @impl true
  def start_link(ref, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def callback_mode, do: [:handle_event_function, :state_enter]

  @spec db_status(pid(), :ready_for_query) :: :ok
  def db_status(pid, status), do: :gen_statem.cast(pid, {:db_status, status})

  @impl true
  def init(_), do: :ignore

  def init(ref, trans, opts) do
    Process.flag(:trap_exit, true)
    Helpers.set_max_heap_size(90)

    {:ok, sock} = :ranch.handshake(ref)
    peer_ip = Helpers.peer_ip(sock)
    local = opts[:local] || false

    Logger.metadata(peer_ip: peer_ip, local: local, state: :init)
    :ok = trans.setopts(sock, active: @switch_active_count)
    Logger.debug("ClientHandler is: #{inspect(self())}")

    data = Data.new({:gen_tcp, sock}, trans, peer_ip, local, opts.mode)

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :handshake, data)
  end

  @impl true
  def handle_event(:info, {_proto, _, <<"GET", _::binary>>}, :handshake, data) do
    Logger.debug("ClientHandler: Client is trying to request HTTP")

    HandlerHelpers.sock_send(
      data.sock,
      "HTTP/1.1 204 OK\r\nx-app-version: #{Application.spec(:supavisor, :vsn)}\r\n\r\n"
    )

    {:stop, :normal}
  end

  # cancel request
  def handle_event(:info, {_, _, Server.cancel_message(pid, key)}, _state, _) do
    Logger.debug("ClientHandler: Got cancel query for #{inspect({pid, key})}")
    :ok = Cancel.send_cancel_query(pid, key)
    {:stop, :normal}
  end

  # send cancel request to db
  def handle_event(:info, :cancel_query, state, data) do
    :ok = Cancel.maybe_forward_cancel_to_db(state, data)
    :keep_state_and_data
  end

  def handle_event(
        :info,
        {:tcp, _, Server.ssl_request_message()},
        :handshake,
        %{sock: sock} = data
      ) do
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
          :ok = HandlerHelpers.setopts(socket, active: @switch_active_count)
          {:keep_state, %{data | sock: socket, ssl: true}}

        error ->
          Logger.error("ClientHandler: SSL handshake error: #{inspect(error)}")
          Telem.client_join(:fail, data.id)
          {:stop, :normal}
      end
    else
      Logger.error(
        "ClientHandler: User requested SSL connection but no downstream cert/key found"
      )

      :ok = HandlerHelpers.sock_send(data.sock, "N")
      :keep_state_and_data
    end
  end

  def handle_event(:info, {_, _, bin}, :handshake, _) when byte_size(bin) > 1024 do
    Logger.error("ClientHandler: Startup packet too large #{byte_size(bin)}")
    {:stop, :normal}
  end

  def handle_event(:info, {_, _, bin}, :handshake, data) do
    case ProtocolHelpers.parse_startup_packet(bin) do
      {:ok, {type, {user, tenant_or_alias, db_name, search_path}}, app_name, _log_level} ->
        event = {:hello, {type, {user, tenant_or_alias, db_name, search_path}}}

        {:keep_state, %{data | app_name: app_name}, {:next_event, :internal, event}}

      {:error, {:invalid_user_info, {:invalid_format, {user, _}}} = reason} ->
        # Extract tenant from the attempted parsing for telemetry
        {_, {_, tenant_or_alias, _}} = HandlerHelpers.parse_user_info(%{"user" => user})
        Telem.client_join(:fail, tenant_or_alias)
        Error.maybe_log_and_send_error(data.sock, {:error, reason})
        {:stop, :normal}

      {:error, error} ->
        Logger.error("ClientHandler: Client startup message error: #{inspect(error)}")
        Telem.client_join(:fail, data.id)
        {:stop, :normal}
    end
  end

  def handle_event(
        :internal,
        {:hello, {type, {user, tenant_or_alias, db_name, search_path}}},
        :handshake,
        %{sock: sock} = data
      ) do
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

        Logger.metadata(
          project: tenant_or_alias,
          user: user,
          mode: data.mode,
          type: type,
          db_name: db_name,
          app_name: data.app_name
        )

        {:ok, addr} = HandlerHelpers.addr_from_sock(sock)

        cond do
          !data.local and info.tenant.enforce_ssl and !data.ssl ->
            Error.maybe_log_and_send_error(sock, {:error, :ssl_required, user})
            Telem.client_join(:fail, id)
            {:stop, :normal}

          HandlerHelpers.filter_cidrs(info.tenant.allow_list, addr) == [] ->
            Error.maybe_log_and_send_error(sock, {:error, :address_not_allowed, addr})
            Telem.client_join(:fail, id)
            {:stop, :normal}

          true ->
            new_data = Data.set_tenant_info(data, info, user, id, db_name, data.mode)

            case Auth.get_user_secrets(data.id, info, user, tenant_or_alias) do
              {:ok, auth_secrets} ->
                Logger.debug("ClientHandler: Authentication method: #{inspect(auth_secrets)}")
                {:keep_state, new_data, {:next_event, :internal, {:handle, auth_secrets, info}}}

              {:error, reason} ->
                Error.maybe_log_and_send_error(sock, {:error, :auth_error, reason}, :handshake)
                Telem.client_join(:fail, id)
                {:stop, :normal}
            end
        end

      {:error, reason} ->
        Error.maybe_log_and_send_error(
          sock,
          {:error, :tenant_not_found, reason, type, user, tenant_or_alias}
        )

        Telem.client_join(:fail, data.id)
        {:stop, :normal}
    end
  end

  def handle_event(
        :internal,
        {:handle, {method, secrets}, info},
        _state,
        %{sock: sock} = data
      ) do
    Logger.debug("ClientHandler: Handle exchange, auth method: #{inspect(method)}")

    case method do
      :auth_query_md5 ->
        auth_context = Auth.create_auth_context(method, secrets, info)
        :ok = HandlerHelpers.sock_send(sock, Server.md5_request(auth_context.salt))

        {:next_state, :auth_md5_wait, %{data | auth_context: auth_context},
         {:timeout, 15_000, :auth_timeout}}

      _scram_method ->
        :ok = HandlerHelpers.sock_send(sock, Server.scram_request())
        auth_context = Auth.create_auth_context(method, secrets, info)

        {:next_state, :auth_scram_first_wait, %{data | auth_context: auth_context},
         {:timeout, 15_000, :auth_timeout}}
    end
  end

  def handle_event(:internal, :subscribe, _state, data) do
    Logger.debug("ClientHandler: Subscribe to tenant #{inspect(data.id)}")

    with {:ok, sup} <-
           Supavisor.start_dist(data.id, data.auth_secrets,
             availability_zone: data.tenant_availability_zone,
             log_level: nil
           ),
         true <-
           if(node(sup) != node() and data.mode in [:transaction, :session],
             do: :proxy,
             else: true
           ),
         {:ok, opts} <- Supavisor.subscribe(sup, data.id) do
      manager_ref = Process.monitor(opts.workers.manager)
      data = Map.merge(data, opts.workers)
      db_connection = maybe_checkout(:both, :on_connect, data)

      data = %{
        data
        | manager: manager_ref,
          db_connection: db_connection,
          idle_timeout: opts.idle_timeout
      }

      Registry.register(@clients_registry, data.id, started_at: System.monotonic_time())

      next =
        if opts.ps == [],
          do: {:timeout, 10_000, :wait_ps},
          else: {:next_event, :internal, {:greetings, opts.ps}}

      {:keep_state, data, next}
    else
      {:error, :max_clients_reached} ->
        Error.maybe_log_and_send_error(data.sock, {:error, :max_clients_reached})
        Telem.client_join(:fail, data.id)
        {:stop, :normal}

      {:error, :max_pools_reached} ->
        Error.maybe_log_and_send_error(data.sock, {:error, :max_pools_reached})
        Telem.client_join(:fail, data.id)
        {:stop, :normal}

      :proxy ->
        case Proxy.prepare_proxy_connection(data) do
          {:ok, updated_data} ->
            Logger.metadata(proxy: true)
            Registry.register(@proxy_clients_registry, data.id, [])

            {:keep_state, updated_data, {:next_event, :internal, :connect_db}}

          {:error, other} ->
            Logger.error("ClientHandler: Subscribe proxy error: #{inspect(other)}")
            timeout_subscribe_or_terminate(data)
        end

      error ->
        Logger.error("ClientHandler: Subscribe error: #{inspect(error)}")
        timeout_subscribe_or_terminate(data)
    end
  end

  def handle_event(:internal, :connect_db, _state, data) do
    Logger.debug("ClientHandler: Trying to connect to DB")

    args = Proxy.build_db_handler_args(data)

    {:ok, db_pid} = DbHandler.start_link(args)
    db_sock = DbHandler.checkout(db_pid, data.sock, self())
    {:keep_state, %{data | db_connection: {nil, db_pid, db_sock}, mode: :proxy}}
  end

  def handle_event(:internal, {:greetings, ps}, _state, %{sock: sock} = data) do
    {header, <<pid::32, key::32>> = payload} = Server.backend_key_data()
    msg = [ps, [header, payload], Server.ready_for_query()]
    :ok = Cancel.listen_cancel_query(pid, key)
    :ok = HandlerHelpers.sock_send(sock, msg)
    Telem.client_connection_time(data.connection_start, data.id)
    {:next_state, :idle, data, handle_actions(data)}
  end

  def handle_event(:timeout, :subscribe, _state, _) do
    {:keep_state_and_data, {:next_event, :internal, :subscribe}}
  end

  def handle_event(:timeout, :wait_ps, _state, data) do
    Logger.warning(
      "ClientHandler: Wait parameter status timeout, send default #{inspect(data.ps)}}"
    )

    ps = Server.encode_parameter_status(data.ps)
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  def handle_event(:timeout, :idle_terminate, _state, data) do
    Logger.warning("ClientHandler: Terminate an idle connection by #{data.idle_timeout} timeout")
    {:stop, :normal}
  end

  def handle_event(:timeout, :heartbeat_check, _state, data) do
    Logger.debug("ClientHandler: Send heartbeat to client")
    HandlerHelpers.sock_send(data.sock, Server.application_name())
    {:keep_state_and_data, {:timeout, data.heartbeat_interval, :heartbeat_check}}
  end

  def handle_event(:info, {:parameter_status, ps}, :connecting, _) do
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  def handle_event(:info, {:ssl_error, sock, reason}, _, %{sock: {_, sock}}) do
    Logger.error("ClientHandler: TLS error #{inspect(reason)}")
    :keep_state_and_data
  end

  # client closed connection
  def handle_event(_, {closed, _}, state, data)
      when closed in [:tcp_closed, :ssl_closed] do
    level =
      if state == :idle or data.mode in [:proxy, :session] do
        :info
      else
        :warning
      end

    Logger.log(
      level,
      "ClientHandler: #{closed} socket closed while state was #{state} (#{data.mode})"
    )

    {:stop, :normal}
  end

  # linked DbHandler went down
  def handle_event(:info, {:EXIT, db_pid, reason}, _state, data) do
    Error.maybe_log_and_send_error(data.sock, {:error, :db_handler_exited, db_pid, reason})
    {:stop, :normal}
  end

  # pool's manager went down
  def handle_event(:info, {:DOWN, ref, _, _, reason}, state, %{manager: ref} = data) do
    Logger.error(
      "ClientHandler: Manager #{inspect(data.manager)} went down #{inspect(reason)} state #{inspect(state)}"
    )

    case {state, reason} do
      {_, :shutdown} -> {:stop, {:shutdown, :manager_shutdown}}
      {:idle, _} -> {:next_state, :connecting, data, {:next_event, :internal, :subscribe}}
      {:connecting, _} -> {:keep_state_and_data, {:next_event, :internal, :subscribe}}
      {:busy, _} -> {:stop, {:shutdown, :manager_down}}
    end
  end

  # emulate handle_cast
  def handle_event(:cast, {:db_status, :ready_for_query}, :busy, data) do
    Logger.debug("ClientHandler: Client is ready")

    db_connection = maybe_checkin(data.mode, data.pool, data.db_connection)

    {_, stats} =
      if data.local,
        do: {nil, data.stats},
        else: Telem.network_usage(:client, data.sock, data.id, data.stats)

    Telem.client_query_time(data.query_start, data.id)

    {:next_state, :idle, %{data | db_connection: db_connection, stats: stats},
     handle_actions(data)}
  end

  def handle_event(:info, {sock_error, _sock, msg}, _state, _data)
      when sock_error in [:tcp_error, :ssl_error] do
    Logger.error("ClientHandler: Socket error: #{inspect(msg)}")

    {:stop, {:shutdown, {:socket_error, msg}}}
  end

  def handle_event(:info, {event, _socket}, _, data) when event in [:tcp_passive, :ssl_passive] do
    HandlerHelpers.setopts(data.sock, active: @switch_active_count)
    :keep_state_and_data
  end

  # Authentication state handlers

  # MD5 authentication - waiting for password response
  def handle_event(:info, {proto, _socket, bin}, :auth_md5_wait, data) when proto in @proto do
    auth_context = data.auth_context

    with {:ok, client_md5} <- Auth.parse_auth_message(bin, auth_context.method),
         {:ok, key} <-
           Auth.validate_credentials(
             auth_context.method,
             auth_context.secrets.().secret,
             auth_context.salt,
             client_md5
           ) do
      handle_auth_success(data.sock, {auth_context.method, auth_context.secrets}, key, data)
    else
      {:error, reason} ->
        handle_auth_failure(data.sock, reason, data, :auth_md5_wait)
    end
  end

  # SCRAM authentication - waiting for first message
  def handle_event(:info, {proto, _socket, bin}, :auth_scram_first_wait, data)
      when proto in @proto do
    auth_context = data.auth_context

    case Auth.parse_auth_message(bin, auth_context.method) do
      {:ok, {user, nonce, channel}} ->
        {message, signatures} =
          Auth.prepare_auth_challenge(
            auth_context.method,
            auth_context.secrets,
            nonce,
            user,
            channel
          )

        :ok = HandlerHelpers.sock_send(data.sock, Server.exchange_message(:first, message))

        new_auth_context = Auth.update_auth_context_with_signatures(auth_context, signatures)
        new_data = %{data | auth_context: new_auth_context}
        {:next_state, :auth_scram_final_wait, new_data, {:timeout, 15_000, :auth_timeout}}

      {:error, reason} ->
        handle_auth_failure(data.sock, reason, data, :auth_scram_first_wait)
    end
  end

  # SCRAM authentication - waiting for final response
  def handle_event(:info, {proto, _socket, bin}, :auth_scram_final_wait, data)
      when proto in @proto do
    auth_context = data.auth_context

    with {:ok, p} <- Auth.parse_auth_message(bin, auth_context.method),
         {:ok, key} <-
           Auth.validate_credentials(
             auth_context.method,
             auth_context.secrets,
             auth_context.signatures,
             p
           ) do
      message = Auth.build_scram_final_response(auth_context)
      :ok = HandlerHelpers.sock_send(data.sock, message)
      handle_auth_success(data.sock, {auth_context.method, auth_context.secrets}, key, data)
    else
      {:error, reason} ->
        handle_auth_failure(data.sock, reason, data, :auth_scram_final_wait)
    end
  end

  # Authentication timeout handler
  def handle_event(:timeout, :auth_timeout, auth_state, data)
      when auth_state in [:auth_md5_wait, :auth_scram_first_wait, :auth_scram_final_wait] do
    handle_auth_failure(data.sock, {:timeout, auth_state}, data, auth_state)
  end

  def handle_event(:enter, old_state, new_state, data) do
    Logger.metadata(state: new_state)

    case {old_state, new_state} do
      {:idle, :busy} ->
        {:next_state, new_state, data}

      {:busy, :idle} ->
        {:next_state, new_state, data}

      _ ->
        now = System.monotonic_time()
        time_in_previous_state = now - data.state_entered_at

        :telemetry.execute(
          [:supavisor, :client_handler, :state],
          %{duration: time_in_previous_state},
          %{
            from_state: old_state,
            to_state: new_state
          }
        )

        {:next_state, new_state, %{data | state_entered_at: now}}
    end
  end

  # Terminate request
  def handle_event(_kind, {proto, _, <<?X, 4::32>>}, :idle, _data) when proto in @proto do
    Logger.info("ClientHandler: Terminate received from client")
    {:stop, :normal}
  end

  # Sync when idle and no db_connection - return sync directly
  def handle_event(
        _kind,
        {proto, _, <<?S, 4::32, _::binary>>},
        :idle,
        %{db_connection: nil} = data
      )
      when proto in @proto do
    Logger.debug("ClientHandler: Receive sync")
    :ok = HandlerHelpers.sock_send(data.sock, Server.ready_for_query())

    {:keep_state, data, handle_actions(data)}
  end

  # Sync in other states - send to db
  def handle_event(_kind, {proto, _, <<?S, 4::32, _::binary>> = msg}, _state, data)
      when proto in @proto do
    Logger.debug("ClientHandler: Receive sync")
    :ok = sock_send(msg, data)

    {:keep_state, data, handle_actions(data)}
  end

  # Any message when idle - checkout and send to db
  def handle_event(_kind, {proto, socket, msg}, :idle, data) when proto in @proto do
    db_connection = maybe_checkout(:both, :on_query, data)

    {:next_state, :busy,
     %{data | db_connection: db_connection, query_start: System.monotonic_time()},
     [{:next_event, :internal, {proto, socket, msg}}]}
  end

  # Any message when busy: send to db
  def handle_event(_kind, {proto, _, msg}, :busy, data) when proto in @proto do
    case handle_data(msg, data) do
      {:ok, updated_data} ->
        {:keep_state, updated_data}

      {:error, reason} ->
        {:stop, {:shutdown, reason}}
    end
  end

  def handle_event(type, content, state, _data) do
    msg = [
      {"type", type},
      {"content", content},
      {"state", state}
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

    # TODO: ensure these errors are forwarded properly on proxy
    error_type =
      case data.mode do
        :session -> {:error, :session_timeout}
        :transaction -> {:error, :transaction_timeout}
      end

    Error.maybe_log_and_send_error(data.sock, error_type)
  end

  def terminate(reason, state, _data) do
    Logger.metadata(state: state)
    Logger.debug("ClientHandler: terminating with reason #{inspect(reason)}")
  end

  ## Internal functions

  defp prepare_retry_transition(sock, {method, secrets}, data) do
    auth_context = data.auth_context
    updated_auth_context = %{auth_context | method: method, secrets: secrets}

    case method do
      :auth_query_md5 ->
        salt = :crypto.strong_rand_bytes(4)
        :ok = HandlerHelpers.sock_send(sock, Server.md5_request(salt))
        final_auth_context = %{updated_auth_context | salt: salt}

        {:next_state, :auth_md5_wait, %{data | auth_context: final_auth_context},
         {:timeout, 15_000, :auth_timeout}}

      _scram_method ->
        :ok = HandlerHelpers.sock_send(sock, Server.scram_request())

        {:next_state, :auth_scram_first_wait, %{data | auth_context: updated_auth_context},
         {:timeout, 15_000, :auth_timeout}}
    end
  end

  defp handle_auth_success(sock, {method, secrets}, client_key, data) do
    final_secrets = Auth.prepare_final_secrets(secrets, client_key)

    Logger.info("ClientHandler: Connection authenticated")
    :ok = HandlerHelpers.sock_send(sock, Server.authentication_ok())
    Telem.client_join(:ok, data.id)

    auth = Map.merge(data.auth, %{secrets: final_secrets, method: method})

    conn_type =
      if data.mode == :proxy,
        do: :connect_db,
        else: :subscribe

    {:next_state, :connecting,
     %{data | auth_context: nil, auth_secrets: {method, final_secrets}, auth: auth},
     {:next_event, :internal, conn_type}}
  end

  defp handle_auth_failure(sock, reason, data, context) do
    auth_context = data.auth_context

    case Auth.handle_auth_retry(
           auth_context.method,
           reason,
           data.id,
           auth_context.info,
           data.tenant,
           data.user,
           {auth_context.method, auth_context.secrets}
         ) do
      {:should_retry, new_secrets} ->
        prepare_retry_transition(sock, new_secrets, data)

      :no_retry ->
        Error.maybe_log_and_send_error(sock, {:error, :auth_error, reason, data.user}, context)
        Telem.client_join(:fail, data.id)
        {:stop, :normal}
    end
  end

  @spec maybe_checkout(:both, :on_connect | :on_query, map) :: Data.db_connection()
  defp maybe_checkout(_, _, %{mode: mode, db_connection: {pool, db_pid, db_sock}})
       when is_pid(db_pid) and mode in [:session, :proxy] do
    {pool, db_pid, db_sock}
  end

  defp maybe_checkout(_, :on_connect, %{mode: :transaction}), do: nil

  defp maybe_checkout(_, _, data) do
    start = System.monotonic_time(:microsecond)
    db_pid = :poolboy.checkout(data.pool, true, data.timeout)
    Process.link(db_pid)
    db_sock = DbHandler.checkout(db_pid, data.sock, self())
    same_box = if node(db_pid) == node(), do: :local, else: :remote
    Telem.pool_checkout_time(System.monotonic_time(:microsecond) - start, data.id, same_box)
    {data.pool, db_pid, db_sock}
  end

  @spec maybe_checkin(:proxy, pool_pid :: pid(), Data.db_connection()) :: Data.db_connection()
  defp maybe_checkin(:transaction, _pool, nil), do: nil

  defp maybe_checkin(:transaction, pool, {_, db_pid, _}) do
    Process.unlink(db_pid)
    :poolboy.checkin(pool, db_pid)
    nil
  end

  defp maybe_checkin(:session, _, db_connection), do: db_connection
  defp maybe_checkin(:proxy, _, db_connection), do: db_connection

  @spec handle_data(binary(), map()) :: {:ok, map()} | {:error, atom()}
  defp handle_data(data_to_send, data) do
    Logger.debug(
      "ClientHandler: Forward pkt to db #{Debug.packet_to_string(data_to_send, :frontend)} #{inspect(data.db_connection)}"
    )

    with {:ok, new_stream_state, pkts} <-
           ProtocolHelpers.process_client_packets(data_to_send, data.mode, data),
         :ok <- sock_send(pkts, data) do
      {:ok, %{data | stream_state: new_stream_state}}
    else
      error ->
        Error.maybe_log_and_send_error(data.sock, error, "sending query")
        {:error, elem(error, 1)}
    end
  end

  @spec handle_actions(map) :: [{:timeout, non_neg_integer, atom}]
  defp handle_actions(%{} = data) do
    heartbeat =
      if data.heartbeat_interval > 0,
        do: [{:timeout, data.heartbeat_interval, :heartbeat_check}],
        else: []

    idle = if data.idle_timeout > 0, do: [{:timeout, data.idle_timeout, :idle_timeout}], else: []

    idle ++ heartbeat
  end

  @spec sock_send([PreparedStatements.handled_pkt()] | binary(), map()) :: :ok | {:error, term()}
  defp sock_send(bin_or_pkts, data) do
    {_pool, db_handler, db_sock} = data.db_connection

    case bin_or_pkts do
      pkts when is_list(pkts) ->
        # Chunking to ensure we send bigger packets
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

      bin ->
        HandlerHelpers.sock_send(elem(data.db_connection, 2), bin)
    end
  end

  @spec timeout_subscribe_or_terminate(map()) :: :gen_statem.handle_event_result()
  def timeout_subscribe_or_terminate(%{subscribe_retries: subscribe_retries} = data) do
    if subscribe_retries < @subscribe_retries do
      Logger.warning("ClientHandler: Retry subscribe #{inspect(subscribe_retries)}")

      {:keep_state, %{data | subscribe_retries: subscribe_retries + 1},
       {:timeout, @timeout_subscribe, :subscribe}}
    else
      Error.maybe_log_and_send_error(data.sock, {:error, :subscribe_retries_exhausted})
      {:stop, :normal}
    end
  end
end
