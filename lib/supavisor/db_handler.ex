defmodule Supavisor.DbHandler do
  @moduledoc """
  This module contains functions to start a link with the database, send requests to the database, and handle incoming messages from clients.
  It uses the Supavisor.Protocol.Server module to decode messages from the database and sends messages to clients Supavisor.ClientHandler.
  """

  require Logger

  @behaviour :gen_statem

  alias Supavisor, as: S
  alias Supavisor.ClientHandler, as: Client
  alias Supavisor.Helpers, as: H
  alias Supavisor.HandlerHelpers, as: HH
  alias Supavisor.{Monitoring.Telem, Protocol.Server}

  @type state :: :connect | :authentication | :idle | :busy

  @reconnect_timeout 2_500
  @sock_closed [:tcp_closed, :ssl_closed]
  @proto [:tcp, :ssl]
  @async_send_limit 1_000

  def start_link(config) do
    :gen_statem.start_link(__MODULE__, config, hibernate_after: 5_000)
  end

  @spec call(pid(), pid(), binary()) :: :ok | {:error, any()} | {:buffering, non_neg_integer()}
  def call(pid, caller, msg), do: :gen_statem.call(pid, {:db_call, caller, msg}, 15_000)

  @spec get_state_and_mode(pid()) :: {:ok, {state, Supavisor.mode()}} | {:error, term()}
  def get_state_and_mode(pid) do
    try do
      {:ok, :gen_statem.call(pid, :get_state_and_mode, 5_000)}
    catch
      error, reason -> {:error, {error, reason}}
    end
  end

  @spec stop(pid()) :: :ok
  def stop(pid), do: :gen_statem.stop(pid, :client_termination, 5_000)

  @impl true
  def init(args) do
    Process.flag(:trap_exit, true)
    H.set_log_level(args.log_level)
    H.set_max_heap_size(150)

    {_, tenant} = args.tenant
    Logger.metadata(project: tenant, user: args.user, mode: args.mode)

    data = %{
      id: args.id,
      sock: nil,
      caller: nil,
      sent: false,
      auth: args.auth,
      user: args.user,
      tenant: args.tenant,
      buffer: [],
      anon_buffer: [],
      db_state: nil,
      parameter_status: %{},
      nonce: nil,
      messages: "",
      server_proof: nil,
      stats: %{},
      mode: args.mode,
      replica_type: args.replica_type
    }

    Telem.handler_action(:db_handler, :started, args.id)
    {:ok, :connect, data, {:next_event, :internal, :connect}}
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  @impl true
  def handle_event(:internal, _, :connect, %{auth: auth} = data) do
    Logger.debug("DbHandler: Try to connect to DB")

    sock_opts = [
      :binary,
      {:packet, :raw},
      {:active, false},
      auth.ip_version
    ]

    reconnect_callback = {:keep_state_and_data, {:state_timeout, @reconnect_timeout, :connect}}

    Telem.handler_action(:db_handler, :db_connection, data.id)

    case :gen_tcp.connect(auth.host, auth.port, sock_opts) do
      {:ok, sock} ->
        Logger.debug("DbHandler: auth #{inspect(auth, pretty: true)}")

        case try_ssl_handshake({:gen_tcp, sock}, auth) do
          {:ok, sock} ->
            case send_startup(sock, auth) do
              :ok ->
                :ok = activate(sock)
                {:next_state, :authentication, %{data | sock: sock}}

              {:error, reason} ->
                Logger.error("DbHandler: Send startup error #{inspect(reason)}")
                reconnect_callback
            end

          {:error, error} ->
            Logger.error("DbHandler: Handshake error #{inspect(error)}")
            reconnect_callback
        end

      other ->
        Logger.error(
          "DbHandler: Connection failed #{inspect(other)} to #{inspect(auth.host)}:#{inspect(auth.port)}"
        )

        reconnect_callback
    end
  end

  def handle_event(:state_timeout, :connect, _state, _) do
    Logger.warning("DbHandler: Reconnect")
    {:keep_state_and_data, {:next_event, :internal, :connect}}
  end

  def handle_event(:info, {proto, _, bin}, :authentication, data) when proto in @proto do
    dec_pkt = Server.decode(bin)
    Logger.debug("DbHandler: dec_pkt, #{inspect(dec_pkt, pretty: true)}")

    resp =
      Enum.reduce(dec_pkt, {%{}, nil}, fn
        %{tag: :parameter_status, payload: {k, v}}, {ps, db_state} ->
          {Map.put(ps, k, v), db_state}

        %{tag: :ready_for_query, payload: db_state}, {ps, _} ->
          {:ready_for_query, ps, db_state}

        %{tag: :backend_key_data, payload: payload}, acc ->
          key = self()
          conn = %{host: data.auth.host, port: data.auth.port, ip_ver: data.auth.ip_version}
          Registry.register(Supavisor.Registry.PoolPids, key, Map.merge(payload, conn))
          Logger.debug("DbHandler: Backend #{inspect(key)} data: #{inspect(payload)}")
          acc

        %{payload: {:authentication_sasl_password, methods_b}}, {ps, _} ->
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
                :ok = sock_send(data.sock, bin)
                nonce

              other ->
                Logger.error("DbHandler: Undefined sasl method #{inspect(other)}")
                nil
            end

          {ps, :authentication_sasl, nonce}

        %{payload: {:authentication_server_first_message, server_first}}, {ps, _}
        when data.auth.require_user == false ->
          nonce = data.nonce
          server_first_parts = H.parse_server_first(server_first, nonce)

          {client_final_message, server_proof} =
            H.get_client_final(
              :auth_query,
              data.auth.secrets.(),
              server_first_parts,
              nonce,
              data.auth.secrets.().user,
              "biws"
            )

          bin = :pgo_protocol.encode_scram_response_message(client_final_message)
          :ok = sock_send(data.sock, bin)

          {ps, :authentication_server_first_message, server_proof}

        %{payload: {:authentication_server_first_message, server_first}}, {ps, _} ->
          nonce = data.nonce
          server_first_parts = :pgo_scram.parse_server_first(server_first, nonce)

          {client_final_message, server_proof} =
            :pgo_scram.get_client_final(
              server_first_parts,
              nonce,
              data.auth.user,
              data.auth.password.()
            )

          bin = :pgo_protocol.encode_scram_response_message(client_final_message)
          :ok = sock_send(data.sock, bin)

          {ps, :authentication_server_first_message, server_proof}

        %{payload: {:authentication_server_final_message, _server_final}}, acc ->
          acc

        %{payload: {:authentication_md5_password, salt}}, {ps, _} ->
          Logger.debug("DbHandler: dec_pkt, #{inspect(dec_pkt, pretty: true)}")

          digest =
            if data.auth.method == :password do
              H.md5([data.auth.password.(), data.auth.user])
            else
              data.auth.secrets.().secret
            end

          payload = ["md5", H.md5([digest, salt]), 0]
          bin = [?p, <<IO.iodata_length(payload) + 4::signed-32>>, payload]
          :ok = sock_send(data.sock, bin)
          {ps, :authentication_md5}

        %{tag: :error_response, payload: error}, _ ->
          {:error_response, error}

        _e, acc ->
          acc
      end)

    case resp do
      {_, :authentication_sasl, nonce} ->
        {:keep_state, %{data | nonce: nonce}}

      {_, :authentication_server_first_message, server_proof} ->
        {:keep_state, %{data | server_proof: server_proof}}

      {_, :authentication_md5} ->
        {:keep_state, data}

      {:error_response, ["SFATAL", "VFATAL", "C28P01", reason, _, _, _]} ->
        tenant = Supavisor.tenant(data.id)

        for node <- [node() | Node.list()] do
          :erpc.cast(node, fn ->
            Cachex.del(Supavisor.Cache, {:secrets, tenant, data.user})
            Cachex.del(Supavisor.Cache, {:secrets_check, tenant, data.user})

            Registry.dispatch(Supavisor.Registry.TenantClients, data.id, fn entries ->
              for {client_handler, _meta} <- entries,
                  do: send(client_handler, {:disconnect, reason})
            end)
          end)
        end

        Supavisor.stop(data.id)
        Logger.error("DbHandler: Auth error #{inspect(reason)}")
        {:stop, :invalid_password, data}

      {:error_response, error} ->
        Logger.error("DbHandler: Error auth response #{inspect(error)}")
        {:keep_state, data}

      {:ready_for_query, ps, db_state} ->
        Logger.debug(
          "DbHandler: DB ready_for_query: #{inspect(db_state)} #{inspect(ps, pretty: true)}"
        )

        Supavisor.set_parameter_status(data.id, ps)

        {:next_state, :idle, %{data | parameter_status: ps},
         {:next_event, :internal, :check_buffer}}

      other ->
        Logger.error("DbHandler: Undefined auth response #{inspect(other)}")
        {:stop, :auth_error, data}
    end
  end

  def handle_event(:internal, :check_buffer, :idle, %{buffer: buff, caller: caller} = data)
      when is_pid(caller) do
    if buff != [] do
      Logger.debug("DbHandler: Buffer is not empty, try to send #{IO.iodata_length(buff)} bytes")
      buff = Enum.reverse(buff)
      :ok = sock_send(data.sock, buff)
    end

    {:next_state, :busy, %{data | buffer: []}}
  end

  # check if it needs to apply queries from the anon buffer
  def handle_event(:internal, :check_anon_buffer, _, %{anon_buffer: buff, caller: nil} = data) do
    if buff != [] do
      Logger.debug(
        "DbHandler: Anon buffer is not empty, try to send #{IO.iodata_length(buff)} bytes"
      )

      buff = Enum.reverse(buff)
      :ok = sock_send(data.sock, buff)
    end

    {:keep_state, %{data | anon_buffer: []}}
  end

  # the process received message from db without linked caller
  def handle_event(:info, {proto, _, bin}, _, %{caller: nil}) when proto in @proto do
    Logger.debug("DbHandler: Got db response #{inspect(bin)} when caller was nil")
    :keep_state_and_data
  end

  def handle_event(:info, {proto, _, bin}, _, %{replica_type: :read} = data)
      when proto in @proto do
    Logger.debug("DbHandler: Got read replica message #{inspect(bin)}")
    pkts = Server.decode(bin)

    resp =
      cond do
        Server.has_read_only_error?(pkts) ->
          Logger.error("DbHandler: read only error")

          with [_] <- pkts do
            # need to flush ready_for_query if it's not in same packet
            :ok = receive_ready_for_query()
          end

          :read_sql_error

        List.last(pkts).tag == :ready_for_query ->
          :ready_for_query

        true ->
          :continue
      end

    :ok = Client.client_cast(data.caller, bin, resp)

    if resp != :continue do
      {_, stats} = Telem.network_usage(:db, data.sock, data.id, data.stats)
      {:keep_state, %{data | stats: stats, caller: handler_caller(data)}}
    else
      :keep_state_and_data
    end
  end

  def handle_event(:info, {proto, _, bin}, _, %{caller: caller} = data)
      when is_pid(caller) and proto in @proto do
    Logger.debug("DbHandler: Got write replica message #{inspect(bin)}")
    HH.setopts(data.sock, active: :once)
    # check if the response ends with "ready for query"
    ready = check_ready(bin)
    sent = data.sent || 0

    {send_via, progress} =
      case ready do
        {:ready_for_query, :idle} -> {:client_cast, :ready_for_query}
        {:ready_for_query, _} -> {:client_cast, :continue}
        _ when sent < @async_send_limit -> {:client_cast, :continue}
        _ -> {:client_call, :continue}
      end

    :ok = apply(Client, send_via, [data.caller, bin, progress])

    case progress do
      :ready_for_query ->
        {_, stats} = Telem.network_usage(:db, data.sock, data.id, data.stats)
        HH.setopts(data.sock, active: true)

        {:next_state, :idle, %{data | stats: stats, caller: handler_caller(data), sent: false},
         {:next_event, :internal, :check_anon_buffer}}

      :continue ->
        {:keep_state, %{data | sent: sent + 1}}
    end
  end

  def handle_event(:info, {:handle_ps, payload, bin}, _state, data) do
    Logger.notice("DbHandler: Apply prepare statement change #{inspect(payload)}")

    {:keep_state, %{data | anon_buffer: [bin | data.anon_buffer]},
     {:next_event, :internal, :check_anon_buffer}}
  end

  def handle_event({:call, from}, {:db_call, caller, bin}, :idle, %{sock: sock} = data) do
    reply = {:reply, from, sock_send(sock, bin)}
    {:next_state, :busy, %{data | caller: caller}, reply}
  end

  def handle_event({:call, from}, {:db_call, caller, bin}, :busy, %{sock: sock} = data) do
    reply = {:reply, from, sock_send(sock, bin)}
    {:keep_state, %{data | caller: caller}, reply}
  end

  def handle_event({:call, from}, {:db_call, caller, bin}, state, %{buffer: buff} = data) do
    Logger.debug(
      "DbHandler: state #{state} <-- <-- bin #{inspect(byte_size(bin))} bytes, caller: #{inspect(caller)}"
    )

    new_buff = [bin | buff]
    reply = {:reply, from, {:buffering, IO.iodata_length(new_buff)}}
    {:keep_state, %{data | caller: caller, buffer: new_buff}, reply}
  end

  def handle_event(_, {closed, _}, :busy, data) when closed in @sock_closed do
    {:stop, :db_termination, data}
  end

  def handle_event(_, {closed, _}, state, data) when closed in @sock_closed do
    Logger.error("DbHandler: Connection closed when state was #{state}")

    if Application.get_env(:supavisor, :reconnect_on_db_close),
      do: {:next_state, :connect, data, {:state_timeout, @reconnect_timeout, :connect}},
      else: {:stop, :db_termination, data}
  end

  # linked client_handler went down
  def handle_event(_, {:EXIT, pid, reason}, state, data) do
    if reason != :normal do
      Logger.error(
        "DbHandler: ClientHandler #{inspect(pid)} went down with reason #{inspect(reason)}"
      )
    end

    if state == :busy || data.mode == :session do
      :ok = sock_send(data.sock, <<?X, 4::32>>)
      :gen_tcp.close(elem(data.sock, 1))
      {:stop, {:client_handler_down, data.mode}}
    else
      {:keep_state, %{data | caller: nil, buffer: []}}
    end
  end

  def handle_event({:call, from}, :get_state_and_mode, state, data) do
    {:keep_state_and_data, {:reply, from, {state, data.mode}}}
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
  def terminate(:shutdown, _state, data) do
    Telem.handler_action(:db_handler, :stopped, data.id)
    :ok
  end

  def terminate(reason, state, data) do
    Telem.handler_action(:db_handler, :stopped, data.id)

    Logger.error(
      "DbHandler: Terminating with reason #{inspect(reason)} when state was #{inspect(state)}"
    )
  end

  @spec try_ssl_handshake(S.tcp_sock(), map) :: {:ok, S.sock()} | {:error, term()}
  defp try_ssl_handshake(sock, %{upstream_ssl: true} = auth) do
    case sock_send(sock, Server.ssl_request()) do
      :ok -> ssl_recv(sock, auth)
      error -> error
    end
  end

  defp try_ssl_handshake(sock, _), do: {:ok, sock}

  @spec ssl_recv(S.tcp_sock(), map) :: {:ok, S.ssl_sock()} | {:error, term}
  defp ssl_recv({:gen_tcp, sock} = s, auth) do
    case :gen_tcp.recv(sock, 1, 15_000) do
      {:ok, <<?S>>} ->
        ssl_connect(s, auth)

      {:ok, <<?N>>} ->
        {:error, :ssl_not_available}

      {:error, _} = error ->
        error
    end
  end

  @spec ssl_connect(S.tcp_sock(), map, pos_integer) :: {:ok, S.ssl_sock()} | {:error, term}
  defp ssl_connect({:gen_tcp, sock}, auth, timeout \\ 5000) do
    opts =
      case auth.upstream_verify do
        :peer ->
          [
            verify: :verify_peer,
            cacerts: [auth.upstream_tls_ca],
            server_name_indication: auth.host,
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

  @spec send_startup(S.sock(), map()) :: :ok | {:error, term}
  defp send_startup(sock, auth) do
    user = get_user(auth)

    msg =
      :pgo_protocol.encode_startup_message([
        {"user", user},
        {"database", auth.database},
        {"application_name", auth.application_name}
      ])

    sock_send(sock, msg)
  end

  @spec sock_send(S.sock(), iodata) :: :ok | {:error, term}
  defp sock_send({mod, sock}, data) do
    mod.send(sock, data)
  end

  @spec activate(S.sock()) :: :ok | {:error, term}
  defp activate({:gen_tcp, sock}) do
    :inet.setopts(sock, active: true)
  end

  defp activate({:ssl, sock}) do
    :ssl.setopts(sock, active: true)
  end

  defp get_user(auth) do
    if auth.require_user do
      auth.secrets.().db_user
    else
      auth.secrets.().user
    end
  end

  @spec receive_ready_for_query() :: :ok | :timeout_error
  defp receive_ready_for_query() do
    receive do
      {_proto, _socket, <<?Z, 5::32, ?I>>} ->
        :ok
    after
      15_000 -> :timeout_error
    end
  end

  @spec handler_caller(map()) :: pid() | nil
  defp handler_caller(%{mode: :session} = data), do: data.caller
  defp handler_caller(_), do: nil

  @spec check_ready(binary()) ::
          {:ready_for_query, :idle | :transaction_block | :failed_transaction_block} | :continue
  def check_ready(bin) do
    bin_size = byte_size(bin)

    case bin do
      <<_::binary-size(bin_size - 6), 90, 0, 0, 0, 5, status_indicator::binary>> ->
        indicator =
          case status_indicator do
            <<?I>> -> :idle
            <<?T>> -> :transaction_block
            <<?E>> -> :failed_transaction_block
            _ -> :continue
          end

        {:ready_for_query, indicator}

      _ ->
        :continue
    end
  end
end
