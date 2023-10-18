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
      ssl: false
    }

    :gen_server.enter_loop(__MODULE__, [hibernate_after: 5_000], state)
  end

  # ssl request from client
  @impl true
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
    {user, external_id} = HH.parse_user_info(hello.payload)
    sni_hostname = HH.try_get_sni(sock)

    Logger.metadata(project: external_id, user: user, mode: "native")

    case Tenants.get_tenant_cache(external_id, sni_hostname) do
      %{db_host: host, db_port: port, external_id: ext_id} ->
        id = Supavisor.id(ext_id, user, :native, :native)
        Registry.register(Supavisor.Registry.TenantClients, id, [])

        payload =
          if !!hello.payload["user"] do
            %{hello.payload | "user" => user}
          else
            hello.payload
          end
          |> Server.encode_startup_packet()

        case connect_local(host, port, payload, state.ssl) do
          {:ok, db_sock} ->
            {:noreply, %{state | db_sock: db_sock}}

          {:error, reason} ->
            Logger.error("Error connecting to tenant db: #{inspect(reason)}")
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

  def handle_info({:tcp_closed, _} = msg, state) do
    Logger.debug("Terminating #{inspect(msg, pretty: true)}")
    {:stop, :normal, state}
  end

  def handle_info({:ssl_closed, _} = msg, state) do
    Logger.debug("Terminating #{inspect(msg, pretty: true)}")
    {:stop, :normal, state}
  end

  def handle_info(msg, state) do
    Logger.error("Undefined message #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  ### Internal functions

  @spec connect_local(String.t(), non_neg_integer, binary, boolean) ::
          {:ok, S.sock()} | {:error, term()}
  defp connect_local(host, port, payload, ssl?) do
    sock_opts = [
      :binary,
      {:packet, :raw},
      {:active, false},
      H.detect_ip_version(host)
    ]

    host = String.to_charlist(host)

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
