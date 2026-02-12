defmodule Supavisor.DbHandler do
  @moduledoc """
  This module contains functions to start a connection to the database, send
  requests to the database, and handle incoming messages from clients.

  The state machine uses the Supavisor.Protocol.Server module to decode messages
  from the database and sends messages to the client socket it received on checkout.
  """

  @behaviour :gen_statem

  require Logger
  require Supavisor.Protocol.Server, as: Server
  require Supavisor.Protocol.MessageStreamer, as: MessageStreamer

  alias Supavisor.Protocol.{PreparedStatements, StartupOptions}

  alias Supavisor.{
    ClientHandler,
    FeatureFlag,
    HandlerHelpers,
    Helpers,
    Monitoring.Telem,
    Protocol.BackendMessageHandler,
    Protocol.Debug,
    Protocol.MessageStreamer,
    Protocol.Server
  }

  @type state ::
          :connect
          | :authentication
          | :idle
          | :busy
          | :terminating_with_error
          | :waiting_for_secrets

  @reconnect_timeout 2_500
  @reconnect_timeout_proxy 500
  @sock_closed [:tcp_closed, :ssl_closed]
  @proto [:tcp, :ssl]
  @switch_active_count Application.compile_env(:supavisor, :switch_active_count)
  @cleanup_buffer_limit 65_536

  @doc """
  Starts a DbHandler state machine

  Accepts two different types of args:

  TODO: details about required arguments in each
  - proxied
  - not proxied
  """
  def start_link(config),
    do: :gen_statem.start_link(__MODULE__, config, hibernate_after: 5_000)

  @doc """
  Checks out a DbHandler process

  Requires a client socket. The DbHandler will forward messages directly to the
  client socket when possible.

  Returns the server socket, which the client may write messages directly to.
  """
  @spec checkout(pid(), Supavisor.sock(), pid(), timeout()) ::
          {:ok, Supavisor.sock()} | {:error, {:exit, term()}} | {:error, map()}
  def checkout(pid, sock, caller, timeout \\ 15_000) do
    :gen_statem.call(pid, {:checkout, sock, caller}, timeout)
  catch
    :exit, reason ->
      {:error, {:exit, reason}}
  end

  @doc """
  Attempts to clean up session state by sending DISCARD ALL to the database.

  The caller is responsible for ensuring that:
  - The DbHandler is NOT actively processing a query
  - The DbHandler is NOT in a transaction (no uncommitted changes)
  - The DbHandler is in session mode (not transaction mode)
  """
  @spec attempt_cleanup(pid()) :: :ok | {:error, term()}
  def attempt_cleanup(db_handler_pid) do
    :gen_statem.call(db_handler_pid, :cleanup, 5_000)
  catch
    :exit, reason ->
      {:error, {:exit, reason}}
  end

  @doc """
  Sends prepared statement packets to a DbHandler

  Different from most packets, prepared statements packets involve state at the DbHandler,
  and hence can't be sent directly to the database socket. Instead, they should be sent
  to the DbHandler through this function.
  """
  @spec handle_prepared_statement_pkts(pid, [PreparedStatements.handled_pkt()]) :: :ok
  def handle_prepared_statement_pkts(pid, pkts) do
    :gen_statem.call(pid, {:handle_ps_pkts, pkts}, 15_000)
  end

  @doc """
  Returns the state and the mode of the DbHandler
  """
  @spec get_state_and_mode(pid()) :: {:ok, {state, Supavisor.mode()}} | {:error, term()}
  def get_state_and_mode(pid) do
    {:ok, :gen_statem.call(pid, :get_state_and_mode, 5_000)}
  catch
    error, reason -> {:error, {error, reason}}
  end

  @doc """
  Stops a DbHandler
  """
  @spec stop(pid()) :: :ok
  def stop(pid) do
    Logger.debug("DbHandler: Stop pid #{inspect(pid)}")
    :gen_statem.stop(pid, {:shutdown, :client_termination}, 5_000)
  end

  @doc """
  Notifies a DbHandler that secrets are now available
  """
  @spec notify_secrets_available(pid()) :: :ok
  def notify_secrets_available(pid) do
    :gen_statem.cast(pid, :secrets_available)
  end

  @impl true
  def init(args) do
    Process.flag(:trap_exit, true)

    {id, config} =
      case args do
        %{proxy: true} ->
          {args.id, args}

        %{} ->
          config = Supavisor.Manager.get_config(args.id)
          {args.id, config}
      end

    Helpers.set_log_level(config.log_level)
    Helpers.set_max_heap_size(90)

    {_, tenant} = config.tenant
    Logger.metadata(project: tenant, user: config.user, mode: config.mode)

    auth =
      if config[:proxy] do
        # Proxy mode: secrets already in config.auth from ClientHandler
        {:ok, config.auth}
      else
        # Pool mode: fetch secrets from TenantCache
        get_auth_with_secrets(config.auth, id)
      end

    {auth_value, manager_ref} =
      case auth do
        {:ok, auth_with_secrets} ->
          {auth_with_secrets, nil}

        {:error, :no_secrets} ->
          Logger.warning("DbHandler: Secrets not available, entering waiting state")
          manager_pid = Supavisor.get_local_manager(id)
          ref = Process.monitor(manager_pid)
          Supavisor.Manager.register_waiting_for_secrets(id, self())
          {config.auth, ref}
      end

    data = %{
      id: id,
      sock: nil,
      auth: auth_value,
      user: config.user,
      tenant: config.tenant,
      tenant_feature_flags: config.tenant_feature_flags,
      db_state: nil,
      parameter_status: %{},
      nonce: nil,
      server_proof: nil,
      stats: %{},
      prepared_statements: MapSet.new(),
      proxy: Map.get(config, :proxy, false),
      stream_state: MessageStreamer.new_stream_state(BackendMessageHandler),
      mode: config.mode,
      replica_type: config.replica_type,
      caller: Map.get(config, :caller) || nil,
      client_sock: Map.get(config, :client_sock) || nil,
      reconnect_retries: 0,
      terminating_error: nil,
      manager_ref: manager_ref
    }

    Telem.handler_action(:db_handler, :started, id)

    if manager_ref do
      {:ok, :waiting_for_secrets, data}
    else
      {:ok, :connect, data, {:next_event, :internal, :connect}}
    end
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  @impl true
  def handle_event(:internal, :connect, :connect, %{auth: auth} = data) do
    Logger.debug("DbHandler: Try to connect to DB")

    sock_opts = [
      auth.ip_version,
      mode: :binary,
      packet: :raw,
      nodelay: true,
      active: false
    ]

    Telem.handler_action(:db_handler, :db_connection, data.id)

    case :gen_tcp.connect(auth.host, auth.port, sock_opts) do
      {:ok, sock} ->
        # Ensure buffer >= recbuf to avoid unnecessary copying
        # Set once at connection time as best effort; OS may adjust recbuf later via auto-tuning.
        {:ok, [{:recbuf, recbuf}]} = :inet.getopts(sock, [:recbuf])
        :ok = :inet.setopts(sock, buffer: recbuf)

        Logger.debug("DbHandler: auth #{inspect(auth, pretty: true)}")

        case try_ssl_handshake({:gen_tcp, sock}, auth) do
          {:ok, sock} ->
            tenant = if data.mode == :proxy, do: Supavisor.tenant(data.id)
            search_path = Supavisor.search_path(data.id)

            case send_startup(sock, auth, tenant, search_path) do
              :ok ->
                :ok = activate(sock)
                {:next_state, :authentication, %{data | sock: sock}}

              {:error, reason} ->
                Logger.error("DbHandler: Send startup error #{inspect(reason)}")
                handle_connection_failure(reason, data)
            end

          {:error, reason} ->
            Logger.error("DbHandler: Handshake error #{inspect(reason)}")
            maybe_reconnect(reason, data)
        end

      other ->
        Logger.error(
          "DbHandler: Connection failed #{inspect(other)} to #{inspect(auth.host)}:#{inspect(auth.port)}"
        )

        handle_connection_failure(other, data)
    end
  end

  def handle_event(:internal, {:terminate_with_error, error, pool_action}, _state, data) do
    Logger.debug("DbHandler: Transitioning to terminating_with_error state")

    if pool_action == :shutdown_pool and not data.proxy do
      Supavisor.Manager.shutdown_with_error(data.id, error)
    end

    # If not checked out yet, the postponed checkout will handle sending the error
    if data.client_sock != nil do
      encode_and_forward_error(error, data)
    end

    # Use cast to allow postponed events to be processed first
    :gen_statem.cast(self(), :finalize_termination)

    # This state will handle postponed checkout calls by returning the error
    {:next_state, :terminating_with_error, %{data | terminating_error: error}}
  end

  def handle_event(:cast, :finalize_termination, :terminating_with_error, _data) do
    Logger.debug("DbHandler: Stopping from terminating_with_error state")
    {:stop, :normal}
  end

  def handle_event(:state_timeout, :connect, _state, data) do
    retry = data.reconnect_retries
    Logger.warning("DbHandler: Reconnect #{retry} to DB")

    {:keep_state, %{data | reconnect_retries: retry + 1}, {:next_event, :internal, :connect}}
  end

  def handle_event(:state_timeout, :cleanup_timeout, :waiting_cleanup, _data) do
    Logger.error("DbHandler: Cleanup timeout, shutting down")
    {:stop, :normal}
  end

  def handle_event(:info, {proto, _, bin}, :authentication, data) when proto in @proto do
    {:ok, dec_pkt, _} = Server.decode(bin)
    Logger.debug("DbHandler: dec_pkt, #{inspect(dec_pkt, pretty: true)}")

    resp = Enum.reduce(dec_pkt, %{}, &handle_auth_pkts(&1, &2, data))

    case resp do
      {:authentication_sasl, nonce} ->
        {:keep_state, %{data | nonce: nonce}}

      {:authentication_server_first_message, server_proof} ->
        {:keep_state, %{data | server_proof: server_proof}}

      %{authentication_server_final_message: _server_final} ->
        :keep_state_and_data

      %{authentication_ok: true} ->
        :keep_state_and_data

      :authentication_md5 ->
        {:keep_state, data}

      :authentication_cleartext ->
        {:keep_state, data}

      {:error_response, %{"S" => "FATAL", "C" => "28P01"} = error} ->
        reason = error["M"] || "Authentication failed"
        handle_authentication_error(data, reason)
        Logger.error("DbHandler: Auth error #{inspect(error)}")

        {:keep_state_and_data,
         {:next_event, :internal, {:terminate_with_error, error, :keep_pool}}}

      {:error_response, %{"S" => "FATAL", "C" => "3D000"} = error} ->
        Logger.error("DbHandler: Database does not exist: #{inspect(error)}")

        {:keep_state_and_data,
         {:next_event, :internal, {:terminate_with_error, error, :shutdown_pool}}}

      {:error_response, %{"S" => "FATAL", "C" => "42501"} = error} ->
        Logger.error("DbHandler: Insufficient privilege: #{inspect(error)}")

        {:keep_state_and_data,
         {:next_event, :internal, {:terminate_with_error, error, :shutdown_pool}}}

      {:error_response, %{"S" => "FATAL", "C" => "22023"} = error} ->
        Logger.error("DbHandler: Invalid parameter value: #{inspect(error)}")

        {:keep_state_and_data,
         {:next_event, :internal, {:terminate_with_error, error, :shutdown_pool}}}

      {:error_response, error} ->
        Logger.error("DbHandler: Error response during auth: #{inspect(error)}")

        {:keep_state_and_data,
         {:next_event, :internal, {:terminate_with_error, error, :keep_pool}}}

      {:ready_for_query, acc} ->
        ps = acc.ps

        Logger.debug(
          "DbHandler: DB ready_for_query: #{inspect(acc.db_state)} #{inspect(ps, pretty: true)}"
        )

        if data.mode != :proxy do
          Supavisor.set_parameter_status(data.id, ps)
        end

        {:next_state, :idle, %{data | parameter_status: ps, reconnect_retries: 0}}

      other ->
        Logger.error("DbHandler: Undefined auth response #{inspect(other)}")
        {:stop, :auth_error, data}
    end
  end

  # the process received message from db while idle
  def handle_event(:info, {proto, _, bin}, :idle, _data) when proto in @proto do
    Logger.debug("DbHandler: Got db response #{inspect(bin)} when idle")
    :keep_state_and_data
  end

  # forward the message to the client
  def handle_event(:info, {proto, _, bin}, :busy, %{caller: caller} = data)
      when is_pid(caller) and proto in @proto do
    Logger.debug("DbHandler: Got messages: #{Debug.packet_to_string(bin, :backend)}")

    if String.ends_with?(bin, Server.ready_for_query()) do
      ClientHandler.db_status(data.caller, :ready_for_query)
      data = handle_server_messages(bin, data)

      case data.mode do
        :transaction ->
          {_, stats} = Telem.network_usage(:db, data.sock, data.id, data.stats)
          {:next_state, :idle, %{data | stats: stats, caller: nil, client_sock: nil}}

        :proxy ->
          {:keep_state, data}

        :session ->
          {_, stats} = Telem.network_usage(:db, data.sock, data.id, data.stats)
          {:keep_state, %{data | stats: stats}}
      end
    else
      data = handle_server_messages(bin, data)
      {:keep_state, data}
    end
  end

  def handle_event(:info, {proto, _, bin}, :waiting_cleanup, %{caller: caller} = data)
      when is_pid(caller) and proto in @proto do
    buffered_bin = data.pending_bin <> bin

    cond do
      String.ends_with?(buffered_bin, Server.ready_for_query()) ->
        new_data = %{data | caller: nil, waiting_cleanup: nil, pending_bin: nil}
        {:next_state, :idle, new_data, {:reply, data.waiting_cleanup, :ok}}

      byte_size(buffered_bin) > @cleanup_buffer_limit ->
        Logger.error("DbHandler: Cleanup buffer limit exceeded, shutting down")
        {:stop, :normal}

      true ->
        {:keep_state, %{data | pending_bin: buffered_bin}}
    end
  end

  def handle_event({:call, from}, {:handle_ps_pkts, pkts}, :busy, data) do
    {iodata, data} = Enum.reduce(pkts, {[], data}, &handle_prepared_statement_pkt/2)

    {close_pkts, prepared_statements} = evict_exceeding(data)

    :ok = HandlerHelpers.sock_send(data.sock, Enum.reverse([close_pkts | iodata]))

    data = %{
      data
      | stream_state:
          Enum.reduce(close_pkts, data.stream_state, fn _, stream_state ->
            MessageStreamer.update_state(stream_state, fn queue ->
              :queue.in({:intercept, :close}, queue)
            end)
          end),
        prepared_statements: prepared_statements
    }

    {:keep_state, data, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:checkout, _sock, _caller}, :terminating_with_error, data) do
    Logger.debug("DbHandler: checkout call during terminating_with_error, replying with error")
    {:keep_state_and_data, {:reply, from, {:error, data.terminating_error}}}
  end

  def handle_event({:call, from}, {:checkout, _sock, _caller}, :waiting_for_secrets, _data) do
    Logger.debug("DbHandler: checkout call during waiting_for_secrets, replying with error")

    error = %{
      "S" => "FATAL",
      "C" => "28P01",
      "M" =>
        "Authentication credentials are invalid. Please reconnect with fresh credentials to restore pool functionality."
    }

    {:keep_state_and_data, {:reply, from, {:error, error}}}
  end

  def handle_event({:call, from}, {:checkout, sock, caller}, state, data) do
    Logger.debug("DbHandler: checkout call when state was #{state}: #{inspect(caller)}")

    if state in [:idle, :busy] do
      Process.link(caller)

      if data.mode == :proxy do
        bin_ps = Server.encode_parameter_status(data.parameter_status)
        send(caller, {:parameter_status, bin_ps})
      end

      {:next_state, :busy, %{data | client_sock: sock, caller: caller},
       {:reply, from, {:ok, data.sock}}}
    else
      {:keep_state_and_data, :postpone}
    end
  end

  def handle_event({:call, from}, :ps, :busy, data) do
    Logger.debug("DbHandler: get parameter status")
    {:keep_state_and_data, {:reply, from, data.parameter_status}}
  end

  def handle_event({:call, from}, :cleanup, state, data) do
    Logger.debug("DbHandler: Cleanup requested, current state: #{inspect(state)}")

    cond do
      data.mode == :transaction ->
        Logger.error(
          "DbHandler: Cleanup called on transaction mode - only supported in session mode"
        )

        {:keep_state_and_data,
         {:reply, from, {:error, :cleanup_not_supported_in_transaction_mode}}}

      state in [:idle, :busy] ->
        Logger.debug("DbHandler: Starting cleanup, sending DISCARD ALL")
        msg = :pgo_protocol.encode_query_message("DISCARD ALL")
        :ok = HandlerHelpers.sock_send(data.sock, msg)

        {:next_state, :waiting_cleanup,
         Map.merge(data, %{waiting_cleanup: from, pending_bin: <<>>}),
         {:state_timeout, 5_000, :cleanup_timeout}}

      true ->
        Logger.warning("DbHandler: Cannot cleanup in state #{inspect(state)}")
        {:keep_state_and_data, {:reply, from, {:error, :cant_cleanup_now}}}
    end
  end

  def handle_event(_, {closed, _}, :busy, data) when closed in @sock_closed do
    {:stop, {:shutdown, :db_termination}, data}
  end

  def handle_event(_, {closed, _}, state, data) when closed in @sock_closed do
    if state != :terminating_with_error do
      Logger.error("DbHandler: Db connection closed when state was #{state}")
    end

    if Application.get_env(:supavisor, :reconnect_on_db_close),
      do: {:next_state, :connect, data, {:state_timeout, reconnect_timeout(data), :connect}},
      else: {:stop, {:shutdown, :db_termination}, data}
  end

  # linked client_handler went down
  def handle_event(_, {:EXIT, pid, reason}, _state, data) do
    if reason != :normal do
      Logger.error(
        "DbHandler: ClientHandler #{inspect(pid)} went down with reason #{inspect(reason)}"
      )
    end

    HandlerHelpers.sock_send(data.sock, Server.terminate_message())
    HandlerHelpers.sock_close(data.sock)
    {:stop, :normal}
  end

  def handle_event({:call, from}, :get_state_and_mode, state, data) do
    {:keep_state_and_data, {:reply, from, {state, data.mode}}}
  end

  def handle_event(:cast, :secrets_available, :waiting_for_secrets, data) do
    Logger.info("DbHandler: Secrets are now available, transitioning to connect state")

    Process.demonitor(data.manager_ref, [:flush])

    case get_auth_with_secrets(data.auth, data.id) do
      {:ok, auth_with_secrets} ->
        {:next_state, :connect, %{data | auth: auth_with_secrets, manager_ref: nil},
         {:next_event, :internal, :connect}}

      {:error, :no_secrets} ->
        Logger.error("DbHandler: Still no secrets available after notification")
        :keep_state_and_data
    end
  end

  def handle_event(:info, {:DOWN, ref, :process, _pid, reason}, :waiting_for_secrets, data)
      when ref == data.manager_ref do
    Logger.error("DbHandler: Manager died while waiting for secrets: #{inspect(reason)}")
    {:stop, :normal, data}
  end

  def handle_event(:info, {event, _socket}, _, data) when event in [:tcp_passive, :ssl_passive] do
    HandlerHelpers.setopts(data.sock, active: @switch_active_count)
    :keep_state_and_data
  end

  def handle_event(type, content, state, data) do
    msg = [
      {"type", type},
      {"content", content},
      {"state", state},
      {"data", data}
    ]

    Logger.debug("DbHandler: Undefined msg: #{inspect(msg, pretty: true)}")

    :keep_state_and_data
  end

  @impl true
  def terminate(_reason, :terminating_with_error, data) do
    Telem.handler_action(:db_handler, :stopped, data.id)
  end

  def terminate(reason, state, data) do
    Telem.handler_action(:db_handler, :stopped, data.id)

    case reason do
      :normal ->
        :ok

      :shutdown ->
        :ok

      reason ->
        Logger.error(
          "DbHandler: Terminating with reason #{inspect(reason)} when state was #{inspect(state)}"
        )
    end
  end

  @impl true
  def format_status(status) do
    Map.put(status, :queue, [])
  end

  @spec encode_and_forward_error(map(), map()) :: :ok | :noop
  defp encode_and_forward_error(message, data) do
    case data do
      %{client_sock: sock} when not is_nil(sock) ->
        HandlerHelpers.sock_send(
          sock,
          Server.encode_error_message(message)
        )

      _other ->
        :noop
    end
  end

  @spec try_ssl_handshake(Supavisor.tcp_sock(), map) :: {:ok, Supavisor.sock()} | {:error, term()}
  defp try_ssl_handshake(sock, %{upstream_ssl: true} = auth) do
    case HandlerHelpers.sock_send(sock, Server.ssl_request()) do
      :ok -> ssl_recv(sock, auth)
      error -> error
    end
  end

  defp try_ssl_handshake(sock, _), do: {:ok, sock}

  @spec ssl_recv(Supavisor.tcp_sock(), map) :: {:ok, Supavisor.ssl_sock()} | {:error, term}
  defp ssl_recv({:gen_tcp, sock} = s, auth) do
    case :gen_tcp.recv(sock, 1, 15_000) do
      {:ok, <<?S>>} -> ssl_connect(s, auth)
      {:ok, <<?N>>} -> {:error, :ssl_not_available}
      {:error, _} = error -> error
    end
  end

  @spec ssl_connect(Supavisor.tcp_sock(), map, pos_integer) ::
          {:ok, Supavisor.ssl_sock()} | {:error, term}
  defp ssl_connect({:gen_tcp, sock}, auth, timeout \\ 5000) do
    opts =
      case auth.upstream_verify do
        :peer ->
          [
            verify: :verify_peer,
            cacerts: [auth.upstream_tls_ca],
            # unclear behavior on pg14
            server_name_indication: auth.sni_hostname || auth.host,
            customize_hostname_check: [{:match_fun, fn _, _ -> true end}]
          ]

        :none ->
          [verify: :verify_none]
      end

    case :ssl.connect(sock, opts, timeout) do
      {:ok, ssl_sock} ->
        {:ok, {:ssl, ssl_sock}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec send_startup(Supavisor.sock(), map(), String.t() | nil, String.t() | nil) ::
          :ok | {:error, term}
  def send_startup(sock, auth, tenant, search_path) do
    user =
      if is_nil(tenant), do: get_user(auth), else: "#{get_user(auth)}.#{tenant}"

    msg =
      :pgo_protocol.encode_startup_message(
        [
          {"user", user},
          {"database", auth.database},
          {"application_name", auth.application_name}
        ] ++
          if(search_path,
            do: [{"options", StartupOptions.encode(%{"search_path" => search_path})}],
            else: []
          )
      )

    HandlerHelpers.sock_send(sock, msg)
  end

  @spec activate(Supavisor.sock()) :: :ok | {:error, term}
  defp activate({:gen_tcp, sock}) do
    :inet.setopts(sock, active: @switch_active_count)
  end

  defp activate({:ssl, sock}) do
    :ssl.setopts(sock, active: @switch_active_count)
  end

  defp get_user(auth) do
    {_method, secrets_fn} = auth.secrets
    secrets_map = secrets_fn.()
    secrets_map.user
  end

  @spec handle_auth_pkts(map(), map(), map()) :: any()
  defp handle_auth_pkts(%{tag: :parameter_status, payload: {k, v}}, acc, _),
    do: update_in(acc, [:ps], fn ps -> Map.put(ps || %{}, k, v) end)

  defp handle_auth_pkts(%{tag: :ready_for_query, payload: db_state}, acc, _),
    do: {:ready_for_query, Map.put(acc, :db_state, db_state)}

  defp handle_auth_pkts(%{tag: :backend_key_data, payload: payload}, acc, data) do
    if data.mode != :proxy do
      Logger.metadata(backend_pid: payload[:pid])
    end

    key = self()
    conn = %{host: data.auth.host, port: data.auth.port, ip_version: data.auth.ip_version}
    Registry.register(Supavisor.Registry.PoolPids, key, Map.merge(payload, conn))
    Logger.debug("DbHandler: Backend #{inspect(key)} data: #{inspect(payload)}")
    Map.put(acc, :backend_key_data, payload)
  end

  defp handle_auth_pkts(%{payload: {:authentication_sasl_password, methods_b}}, _, data) do
    nonce =
      case Server.decode_string(methods_b) do
        {:ok, req_method, _} ->
          Logger.debug("DbHandler: SASL method #{inspect(req_method)}")
          nonce = :pgo_scram.get_nonce(16)
          user = get_user(data.auth)
          client_first = :pgo_scram.get_client_first(user, nonce)
          client_first_size = IO.iodata_length(client_first)

          sasl_initial_response = [
            "SCRAM-SHA-256",
            0,
            <<client_first_size::32-integer>>,
            client_first
          ]

          bin = :pgo_protocol.encode_scram_response_message(sasl_initial_response)
          :ok = HandlerHelpers.sock_send(data.sock, bin)
          nonce

        other ->
          Logger.error("DbHandler: Undefined sasl method #{inspect(other)}")
          nil
      end

    {:authentication_sasl, nonce}
  end

  defp handle_auth_pkts(
         %{payload: {:authentication_server_first_message, server_first}},
         _,
         data
       ) do
    nonce = data.nonce
    server_first_parts = Helpers.parse_server_first(server_first, nonce)

    {_method, secrets_fn} = data.auth.secrets
    secrets = secrets_fn.()

    {client_final_message, server_proof} =
      Helpers.get_client_final(
        data.auth.method,
        secrets,
        server_first_parts,
        nonce,
        secrets.user,
        "biws"
      )

    bin = :pgo_protocol.encode_scram_response_message(client_final_message)
    :ok = HandlerHelpers.sock_send(data.sock, bin)

    {:authentication_server_first_message, server_proof}
  end

  defp handle_auth_pkts(
         %{payload: {:authentication_server_final_message, server_final}},
         acc,
         _data
       ),
       do: Map.put(acc, :authentication_server_final_message, server_final)

  defp handle_auth_pkts(
         %{payload: :authentication_ok},
         acc,
         _data
       ),
       do: Map.put(acc, :authentication_ok, true)

  defp handle_auth_pkts(%{payload: {:authentication_md5_password, salt}} = dec_pkt, _, data) do
    Logger.debug("DbHandler: dec_pkt, #{inspect(dec_pkt, pretty: true)}")

    {_method, secrets_fn} = data.auth.secrets
    secrets = secrets_fn.()

    digest =
      if data.auth.method == :password do
        Helpers.md5([secrets.password, secrets.user])
      else
        secrets.password
      end

    payload = ["md5", Helpers.md5([digest, salt]), 0]
    bin = [?p, <<IO.iodata_length(payload) + 4::signed-32>>, payload]
    :ok = HandlerHelpers.sock_send(data.sock, bin)
    :authentication_md5
  end

  defp handle_auth_pkts(%{payload: :authentication_cleartext_password} = dec_pkt, _, data) do
    Logger.debug("DbHandler: dec_pkt, #{inspect(dec_pkt, pretty: true)}")

    {_method, secrets_fn} = data.auth.secrets
    secrets = secrets_fn.()

    payload = <<secrets.password::binary, 0>>
    bin = [?p, <<IO.iodata_length(payload) + 4::signed-32>>, payload]
    :ok = HandlerHelpers.sock_send(data.sock, bin)
    :authentication_cleartext
  end

  defp handle_auth_pkts(%{tag: :error_response, payload: error}, _acc, _data),
    do: {:error_response, error}

  defp handle_auth_pkts(_e, acc, _data), do: acc

  @spec handle_authentication_error(map(), String.t()) :: any()
  defp handle_authentication_error(%{mode: :proxy}, _reason), do: :ok

  defp handle_authentication_error(%{mode: _other} = data, _reason) do
    tenant = Supavisor.tenant(data.id)
    Supavisor.SecretCache.invalidate(tenant, data.user)
    Supavisor.SecretCache.delete_upstream_auth_secrets(data.id)
  end

  @spec reconnect_timeout(map()) :: pos_integer()
  def reconnect_timeout(%{proxy: true}),
    do: @reconnect_timeout_proxy

  def reconnect_timeout(_),
    do: @reconnect_timeout

  @spec handle_server_messages(binary(), map()) :: map()
  defp handle_server_messages(bin, data) do
    if FeatureFlag.enabled?(data.tenant_feature_flags, "named_prepared_statements") do
      {:ok, updated_data, packets_to_send} = process_backend_streaming(bin, data)

      if packets_to_send != [] do
        HandlerHelpers.sock_send(data.client_sock, packets_to_send)
      end

      updated_data
    else
      HandlerHelpers.sock_send(data.client_sock, bin)

      data
    end
  end

  # If the prepared statement exists for us, it exists for the server, so we just send the
  # bind to the socket. If it doesn't, we must send the parse pkt first.
  #
  # If we received a bind without a parse, we need to intercept the parse response, otherwise,
  # the client will receive an unexpected message.
  defp handle_prepared_statement_pkt({:bind_pkt, stmt_name, pkt, parse_pkt}, {iodata, data}) do
    if stmt_name in data.prepared_statements do
      {[pkt | iodata], data}
    else
      new_data = %{
        data
        | stream_state:
            MessageStreamer.update_state(data.stream_state, fn queue ->
              :queue.in({:intercept, :parse}, queue)
            end),
          prepared_statements: MapSet.put(data.prepared_statements, stmt_name)
      }

      {[[parse_pkt, pkt] | iodata], new_data}
    end
  end

  defp handle_prepared_statement_pkt({:close_pkt, stmt_name, pkt}, {iodata, data}) do
    {[pkt | iodata],
     %{
       data
       | prepared_statements: MapSet.delete(data.prepared_statements, stmt_name),
         stream_state:
           MessageStreamer.update_state(data.stream_state, fn queue ->
             :queue.in({:forward, :close}, queue)
           end)
     }}
  end

  defp handle_prepared_statement_pkt({:describe_pkt, _stmt_name, pkt}, {iodata, data}) do
    {[pkt | iodata], data}
  end

  # If we stop generating unique id per statement, and instead do deterministic ids,
  # we need to potentially drop parse pkts and return a parse response
  defp handle_prepared_statement_pkt({:parse_pkt, stmt_name, pkt}, {iodata, data}) do
    if stmt_name in data.prepared_statements do
      {iodata,
       %{
         data
         | stream_state:
             MessageStreamer.update_state(data.stream_state, fn queue ->
               :queue.in({:inject, :parse}, queue)
             end)
       }}
    else
      prepared_statements = MapSet.put(data.prepared_statements, stmt_name)

      {[pkt | iodata],
       %{
         data
         | prepared_statements: prepared_statements,
           stream_state:
             MessageStreamer.update_state(data.stream_state, fn queue ->
               :queue.in({:forward, :parse}, queue)
             end)
       }}
    end
  end

  defp evict_exceeding(%{prepared_statements: prepared_statements, id: id}) do
    limit = PreparedStatements.backend_limit()

    if MapSet.size(prepared_statements) >= limit do
      count = div(limit, 5)
      to_remove = Enum.take_random(prepared_statements, count) |> MapSet.new()
      close_pkts = Enum.map(to_remove, &PreparedStatements.build_close_pkt/1)
      prepared_statements = MapSet.difference(prepared_statements, to_remove)
      Telem.prepared_statements_evicted(count, id)

      {close_pkts, prepared_statements}
    else
      {[], prepared_statements}
    end
  end

  defp maybe_reconnect(reason, data) do
    max_reconnect_retries = Application.get_env(:supavisor, :reconnect_retries)
    data = %{data | reconnect_retries: data.reconnect_retries + 1}

    if data.reconnect_retries > max_reconnect_retries do
      {:stop, {:failed_to_connect, reason}}
    else
      {:keep_state, data, {:state_timeout, reconnect_timeout(data), :connect}}
    end
  end

  defp process_backend_streaming(bin, data) do
    case MessageStreamer.handle_packets(data.stream_state, bin) do
      {:ok, new_stream_state, packets} ->
        updated_data = %{data | stream_state: new_stream_state}
        {:ok, updated_data, packets}

      err ->
        err
    end
  end

  defp get_auth_with_secrets(auth, id) do
    case Supavisor.SecretCache.get_upstream_auth_secrets(id) do
      {:ok, upstream_auth_secrets} ->
        {:ok, Map.put(auth, :secrets, upstream_auth_secrets)}

      _other ->
        {:error, :no_secrets}
    end
  end

  defp handle_connection_failure(reason, data) do
    if not data.proxy do
      {_, tenant} = data.tenant
      Supavisor.CircuitBreaker.record_failure(tenant, :db_connection)
    end

    maybe_reconnect(reason, data)
  end
end
