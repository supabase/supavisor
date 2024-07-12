defmodule Supavisor.Handlers.Proxy.Db do
  @moduledoc false

  require Logger

  alias Supavisor, as: S
  alias Supavisor.Helpers, as: H
  alias Supavisor.HandlerHelpers, as: HH
  alias Supavisor.{Monitoring.Telem, Protocol.Server}

  @type state :: :connect | :authentication | :idle | :busy

  @sock_closed [:tcp_closed, :ssl_closed]
  @proto [:tcp, :ssl]

  def handle_event(:info, {proto, _, bin}, :db_authentication, data) when proto in @proto do
    dec_pkt = Server.decode(bin)
    Logger.debug("ProxyDb: dec_pkt, #{inspect(dec_pkt, pretty: true)}")
    HH.active_once(data.db_sock)

    resp = Enum.reduce(dec_pkt, %{}, &handle_auth_pkts(&1, &2, data))

    case resp do
      {:authentication_sasl, nonce} ->
        {:keep_state, %{data | nonce: nonce}}

      {:authentication_server_first_message, server_proof} ->
        {:keep_state, %{data | server_proof: server_proof}}

      :authentication_md5 ->
        {:keep_state, data}

      {:error_response, ["SFATAL", "VFATAL", "C28P01", reason, _, _, _]} ->
        Logger.error("ProxyDb: Auth error #{inspect(reason)}")
        {:stop, :invalid_password, data}

      {:error_response, error} ->
        Logger.error("ProxyDb: Error auth response #{inspect(error)}")
        {:keep_state, data}

      {:ready_for_query, acc} ->
        ps = acc.ps
        backend_key_data = acc.backend_key_data
        msg = "ProxyDb: DB ready_for_query: #{inspect(acc.db_state)} #{inspect(ps, pretty: true)}"
        Logger.debug(msg)
        ps_encoded = Server.encode_parameter_status(ps)

        {:next_state, :idle, %{data | parameter_status: ps, backend_key_data: backend_key_data},
         {:next_event, :internal, {:client, {:greetings, ps_encoded}}}}

      other ->
        Logger.error("ProxyDb: Undefined auth response #{inspect(other)}")
        {:stop, :auth_error, data}
    end
  end

  def handle_event(:info, {proto, _, bin}, _, data) when proto in @proto do
    HH.sock_send(data.sock, bin)
    HH.active_once(data.db_sock)
    :keep_state_and_data
  end

  def handle_event(_, {closed, _}, state, data) when closed in @sock_closed do
    Logger.error("ProxyDb: Connection closed when state was #{state}")
    HH.sock_send(data.sock, Server.error_message("XX000", "Database connection closed"))
    HH.sock_close(data.sock)
    {:stop, :db_socket_closed, data}
  end

  ## Internal functions

  @spec handle_auth_pkts(map(), map(), map()) :: any()
  defp handle_auth_pkts(%{tag: :parameter_status, payload: {k, v}}, acc, _),
    do: update_in(acc, [:ps], fn ps -> Map.put(ps || %{}, k, v) end)

  defp handle_auth_pkts(%{tag: :ready_for_query, payload: db_state}, acc, _),
    do: {:ready_for_query, Map.put(acc, :db_state, db_state)}

  defp handle_auth_pkts(%{tag: :backend_key_data, payload: payload}, acc, _),
    do: Map.put(acc, :backend_key_data, payload)

  defp handle_auth_pkts(%{payload: {:authentication_sasl_password, methods_b}}, _, data) do
    nonce =
      case Server.decode_string(methods_b) do
        {:ok, req_method, _} ->
          Logger.debug("ProxyDb: SASL method #{inspect(req_method)}")
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
          :ok = HH.sock_send(data.db_sock, bin)
          nonce

        other ->
          Logger.error("ProxyDb: Undefined sasl method #{inspect(other)}")
          nil
      end

    {:authentication_sasl, nonce}
  end

  defp handle_auth_pkts(
         %{payload: {:authentication_server_first_message, server_first}},
         _,
         data
       )
       when data.auth.require_user == false do
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
    :ok = HH.sock_send(data.db_sock, bin)

    {:authentication_server_first_message, server_proof}
  end

  defp handle_auth_pkts(
         %{payload: {:authentication_server_first_message, server_first}},
         _,
         data
       ) do
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
    :ok = HH.sock_send(data.db_sock, bin)

    {:authentication_server_first_message, server_proof}
  end

  defp handle_auth_pkts(
         %{payload: {:authentication_server_final_message, _server_final}},
         acc,
         _data
       ),
       do: acc

  defp handle_auth_pkts(%{payload: {:authentication_md5_password, salt}} = dec_pkt, _, data) do
    Logger.debug("ProxyDb: dec_pkt, #{inspect(dec_pkt, pretty: true)}")

    digest =
      if data.auth.method == :password do
        H.md5([data.auth.password.(), data.auth.user])
      else
        data.auth.secrets.().secret
      end

    payload = ["md5", H.md5([digest, salt]), 0]
    bin = [?p, <<IO.iodata_length(payload) + 4::signed-32>>, payload]
    :ok = HH.sock_send(data.db_sock, bin)
    :authentication_md5
  end

  defp handle_auth_pkts(%{tag: :error_response, payload: error}, _acc, _data),
    do: {:error_response, error}

  defp handle_auth_pkts(_e, acc, _data), do: acc

  @spec try_ssl_handshake(S.tcp_sock(), map()) :: {:ok, S.db_sock()} | {:error, term()}
  def try_ssl_handshake(sock, %{upstream_ssl: true} = auth) do
    with :ok <- HH.sock_send(sock, Server.ssl_request()) do
      ssl_recv(sock, auth)
    end
  end

  def try_ssl_handshake(sock, _), do: {:ok, sock}

  @spec ssl_recv(S.tcp_sock(), map) :: {:ok, S.ssl_sock()} | {:error, term}
  def ssl_recv({:gen_tcp, sock} = s, auth) do
    case :gen_tcp.recv(sock, 1, 15_000) do
      {:ok, <<?S>>} -> ssl_connect(s, auth)
      {:ok, <<?N>>} -> {:error, :ssl_not_available}
      {:error, _} = error -> error
    end
  end

  @spec ssl_connect(S.tcp_sock(), map, pos_integer) :: {:ok, S.ssl_sock()} | {:error, term}
  def ssl_connect({:gen_tcp, sock}, auth, timeout \\ 5000) do
    opts =
      case auth.upstream_verify do
        :peer ->
          [
            verify: :verify_peer,
            cacerts: [auth.upstream_tls_ca],
            # unclear behavior on pg14
            server_name_indication: auth.sni_host || auth.host,
            customize_hostname_check: [{:match_fun, fn _, _ -> true end}]
          ]

        :none ->
          [verify: :verify_none]
      end

    case :ssl.connect(sock, opts, timeout) do
      {:ok, ssl_sock} -> {:ok, {:ssl, ssl_sock}}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec send_startup(S.db_sock(), map()) :: :ok | {:error, term}
  def send_startup(sock, auth) do
    user = get_user(auth)

    msg =
      :pgo_protocol.encode_startup_message([
        {"user", user},
        {"database", auth.database},
        {"application_name", auth.application_name}
      ])

    HH.sock_send(sock, msg)
  end

  @spec get_user(map) :: String.t()
  def get_user(auth) do
    if auth.require_user,
      do: auth.secrets.().db_user,
      else: auth.secrets.().user
  end
end
