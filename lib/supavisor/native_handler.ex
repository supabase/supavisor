defmodule Supavisor.NativeHandler do
  @moduledoc false
  use GenServer
  @behaviour :ranch_protocol

  require Logger
  alias Supavisor, as: S
  alias Supavisor.Helpers, as: H
  alias Supavisor.HandlerHelpers, as: HH
  alias Supavisor.{Protocol.Server, Tenants}

  @impl true
  def start_link(ref, _sock, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def init(_), do: :ignore

  def init(ref, trans, opts) do
    Logger.debug("NativeHandler is: #{inspect(self())} opts: #{inspect(opts)}",
      pretty: true
    )

    {:ok, sock} = :ranch.handshake(ref)
    :ok = trans.setopts(sock, active: true)

    state = %{
      db_sock: nil,
      client_sock: {:gen_tcp, sock},
      trans: trans,
      acc: nil,
      status: :startup,
      ssl: false,
      db_auth: nil,
      backend_key: nil
    }

    :gen_server.enter_loop(__MODULE__, [hibernate_after: 5_000], state)
  end

  @impl true
  # http healthcheck
  def handle_info({_, sock, <<"GET", _::binary>>}, state) do
    Logger.debug("Client is trying to request HTTP")
    HH.sock_send({:gen_tcp, sock}, "HTTP/1.1 204 OK\r\n\r\n")
    {:stop, :normal, state}
  end

  def handle_info(
        {:tcp, sock, <<16::32, 1234::16, 5678::16, pid::32, key::32>>},
        %{status: :startup, client_sock: {_, sock} = client_sock} = state
      ) do
    Logger.debug("Got cancel query for #{inspect({pid, key})}")
    :ok = HH.send_cancel_query(pid, key)
    :ok = HH.sock_close(client_sock)
    {:stop, :normal, state}
  end

  # ssl request from client
  def handle_info(
        {:tcp, sock, <<_::64>>} = _msg,
        %{status: :startup, client_sock: {_, sock} = client_sock} = state
      ) do
    Logger.debug("Client is trying to connect with SSL")

    downstream_cert = H.downstream_cert()
    downstream_key = H.downstream_key()

    # SSL negotiation, S/N/Error
    if !!downstream_cert and !!downstream_key do
      :ok = HH.setopts(client_sock, active: false)
      :ok = HH.sock_send(client_sock, "S")

      opts = [
        certfile: downstream_cert,
        keyfile: downstream_key
      ]

      case :ssl.handshake(elem(client_sock, 1), opts) do
        {:ok, ssl_sock} ->
          socket = {:ssl, ssl_sock}
          :ok = HH.setopts(socket, active: true)
          {:noreply, %{state | client_sock: socket, ssl: true, status: :proxy}}

        error ->
          Logger.error("SSL handshake error: #{inspect(error)}")
          {:stop, :normal, state}
      end
    else
      Logger.error("User requested SSL connection but no downstream cert/key found")

      :ok = HH.sock_send(client_sock, "N")
      {:noreply, state}
    end
  end

  # send packets to client from db
  def handle_info(
        {_, sock, bin},
        %{db_sock: {_, sock}, backend_key: nil} = state
      ) do
    state =
      bin
      |> Server.decode()
      |> Enum.filter(fn e -> Map.get(e, :tag) == :backend_key_data end)
      |> case do
        [%{payload: %{key: key, pid: pid} = k}] ->
          Logger.debug("Backend key: #{inspect(k)}")
          :ok = HH.listen_cancel_query(pid, key)
          %{state | backend_key: k}

        _ ->
          state
      end

    :ok = HH.sock_send(state.client_sock, bin)
    {:noreply, state}
  end

  def handle_info({_, sock, bin}, %{db_sock: {_, sock}} = state) do
    :ok = HH.sock_send(state.client_sock, bin)
    {:noreply, state}
  end

  # initial db connection and send startup packet
  def handle_info(
        {_, sock, bin},
        %{client_sock: {_, sock}, db_sock: nil} = state
      ) do
    {:ok, hello} = Server.decode_startup_packet(bin)
    Logger.debug("Startup packet: #{inspect(hello, pretty: true)}")
    {_, {user, external_id, db_name}} = HH.parse_user_info(hello.payload)
    sni_hostname = HH.try_get_sni(sock)

    case Tenants.get_tenant_cache(external_id, sni_hostname) do
      %{db_host: host, db_port: port, external_id: ext_id, db_database: db_database} = tenant ->
        db_name = if(db_name != nil, do: db_name, else: db_database)

        Logger.metadata(
          project: external_id,
          user: user,
          mode: "native",
          db_name: db_name
        )

        id = Supavisor.id(ext_id, user, :native, :native, db_name)
        Registry.register(Supavisor.Registry.TenantClients, id, [])

        payload =
          if !!hello.payload["user"] do
            %{hello.payload | "user" => user}
          else
            hello.payload
          end
          |> Server.encode_startup_packet()

        ip_ver = H.detect_ip_version(host)
        host = String.to_charlist(host)

        {:ok, addr} = HH.addr_from_sock(sock)

        unless HH.filter_cidrs(tenant.allow_list, addr) == [] do
          case connect_local(host, port, payload, ip_ver, state.ssl) do
            {:ok, db_sock} ->
              auth = %{host: host, port: port, ip_ver: ip_ver}
              {:noreply, %{state | db_sock: db_sock, db_auth: auth}}

            {:error, reason} ->
              Logger.error("Error connecting to tenant db: #{inspect(reason)}")
              {:stop, :normal, state}
          end
        else
          message = "Address not in tenant allow_list: " <> inspect(addr)
          Logger.error(message)
          :ok = HH.send_error(sock, "XX000", message)
          {:stop, :normal, state}
        end

      _ ->
        Logger.error("Tenant not found: #{inspect({external_id, sni_hostname})}")

        :ok = HH.send_error(state.client_sock, "XX000", "Tenant not found")
        {:stop, :normal, state}
    end
  end

  # send packets to db from client
  def handle_info(
        {_, sock, bin},
        %{client_sock: {_, sock}, db_sock: db_sock} = state
      ) do
    :ok = HH.sock_send(db_sock, bin)
    {:noreply, state}
  end

  def handle_info({closed, _} = msg, state) when closed in [:tcp_closed, :ssl_closed] do
    Logger.debug("Closed socket #{inspect(msg, pretty: true)}")
    {:stop, :normal, state}
  end

  def handle_info(:cancel_query, %{backend_key: key, db_auth: auth} = state) do
    Logger.debug("Cancel query for #{inspect(key)}")
    :ok = HH.cancel_query(auth.host, auth.port, auth.ip_ver, key.pid, key.key)
    {:noreply, state}
  end

  def handle_info(msg, state) do
    Logger.error("Undefined message #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    Logger.debug("Terminate #{inspect(self())}")
    :ok = HH.sock_close(state.db_sock)
    :ok = HH.sock_close(state.client_sock)
  end

  ### Internal functions

  @spec connect_local(keyword, non_neg_integer, binary, atom, boolean) ::
          {:ok, S.sock()} | {:error, term()}
  defp connect_local(host, port, payload, ip_ver, ssl?) do
    sock_opts = [
      :binary,
      {:packet, :raw},
      {:active, false},
      ip_ver
    ]

    with {:ok, sock} <- :gen_tcp.connect(host, port, sock_opts),
         {:ok, sock} <- HH.try_ssl_handshake({:gen_tcp, sock}, ssl?),
         :ok <- HH.sock_send(sock, payload) do
      :ok = HH.activate(sock)
      {:ok, sock}
    else
      {:error, _} = error ->
        error
    end
  end
end
