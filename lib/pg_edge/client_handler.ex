defmodule PgEdge.ClientHandler do
  require Logger
  use GenServer
  @behaviour :ranch_protocol

  alias PgEdge.Protocol.Client
  alias PgEdge.Protocol.Server

  @impl true
  def start_link(ref, _socket, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def init(_opts) do
    {:ok, %{}}
  end

  def init(ref, trans, _opts) do
    {:ok, socket} = :ranch.handshake(ref)
    :ok = trans.setopts(socket, [{:active, true}])
    Logger.info("ClientHandler is: #{inspect(self())}")

    :gen_server.enter_loop(
      __MODULE__,
      [],
      %{
        socket: socket,
        trans: trans,
        connected: false,
        buffer: "",
        db_pid: nil,
        db_socket: nil,
        tenant: nil,
        state: :wait_startup_packet
      }
    )
  end

  @impl true
  def handle_info(
        {:tcp, sock, bin},
        %{socket: socket, state: :wait_startup_packet} = state
      )
      when sock == socket do
    Logger.debug("Startup <-- bin #{inspect(byte_size(bin))}")

    # TODO: implement SSL negotiation
    # SSL negotiation, S/N/Error
    if byte_size(bin) == 8 do
      :gen_tcp.send(socket, "N")
      {:noreply, state}
    else
      hello = Client.decode_startup_packet(bin)
      Logger.warning("Client startup message: #{inspect(hello)}")

      external_id =
        hello.payload["user"]
        |> get_external_id()

      # TODO: check the response
      PgEdge.start_pool(external_id)
      :gen_tcp.send(socket, authentication_ok())
      {:noreply, %{state | state: :idle, tenant: external_id}}
    end
  end

  def handle_info({:tcp, sock, <<?X, 4::32>>}, state) when sock == state.socket do
    Logger.warn("Receive termination")
    {:noreply, state}
  end

  # select 1 stub
  def handle_info({:tcp, sock, <<?Q, 14::32, "SELECT 1;", 0>>}, state)
      when sock == state.socket do
    Logger.info("Receive select 1")
    :gen_tcp.send(state.socket, Server.select_1_response())
    {:noreply, state}
  end

  # receive from a client
  def handle_info({:tcp, sock, bin}, %{tenant: tenant, state: :idle} = state)
      when sock === state.socket do
    db_pid =
      PgEdge.pool_name(tenant)
      |> :poolboy.checkout(true, 60_000)

    state =
      case GenServer.call(db_pid, :change_owner) do
        {:ok, db_socket} ->
          {db_pid, db_socket}

          :gen_tcp.send(db_socket, bin)
          {:noreply, %{state | db_pid: db_pid, db_socket: db_socket, state: :transaction}}

        {:error, reason} ->
          Logger.error("Can't change socket owner: #{inspect(reason)}")
          {:stop, reason, state}
      end
  end

  def handle_info({:tcp, sock, bin}, %{state: :transaction} = state)
      when sock === state.socket do
    :gen_tcp.send(state.db_socket, bin)

    {:noreply, state}
  end

  # send to db
  def handle_info(
        {:tcp, sock, bin},
        %{db_socket: db_socket, socket: socket, state: :transaction} = state
      )
      when sock == db_socket do
    Logger.debug("--> bin #{inspect(byte_size(bin))} bytes")

    :gen_tcp.send(socket, bin)

    state =
      case PgEdge.DbHandler.handle_packets(bin) do
        {:ok, :ready_for_query, rest, :idle} ->
          :gen_tcp.controlling_process(db_socket, state.db_pid)

          PgEdge.pool_name(state.tenant)
          |> :poolboy.checkin(state.db_pid)

          %{state | db_pid: nil, db_socket: nil, state: :idle}

        {:ok, _, rest, _} ->
          state
      end

    {:noreply, state}
  end

  def handle_info({:tcp_closed, _}, state) do
    Logger.info("Client closed connection")
    {:stop, :normal, state}
  end

  def handle_info(msg, state) do
    msg = [
      {"msg", msg},
      {"state", state}
    ]

    Logger.error("Undefined msg: #{inspect(msg, pretty: true)}")

    {:noreply, state}
  end

  # TODO: implement authentication response
  def authentication_ok() do
    [
      # authentication_ok
      <<"R", 0, 0, 0, 8>>,
      <<0, 0, 0, 0>>,
      # parameter_status,<<"application_name">>,<<"nonode@nohost">>
      <<83, 0, 0, 0, 35>>,
      <<"application_name", 0, "nonode@nohost", 0>>,
      # parameter_status,<<"client_encoding">>,<<"UTF8">>
      <<83, 0, 0, 0, 25>>,
      <<99, 108, 105, 101, 110, 116, 95, 101, 110, 99, 111, 100, 105, 110, 103, 0, 85, 84, 70, 56,
        0>>,
      # parameter_status,<<"server_version">>,<<"14.1">>
      <<83, 0, 0, 0, 24>>,
      <<115, 101, 114, 118, 101, 114, 95, 118, 101, 114, 115, 105, 111, 110, 0, "14.1", 0>>,
      # parameter_status,<<"session_authorization">>,<<"postgres">>
      <<83, 0, 0, 0, 35>>,
      <<115, 101, 115, 115, 105, 111, 110, 95, 97, 117, 116, 104, 111, 114, 105, 122, 97, 116,
        105, 111, 110, 0, 112, 111, 115, 116, 103, 114, 101, 115, 0>>,
      # parameter_status,<<"standard_conforming_strings">>,<<"on">>
      <<83, 0, 0, 0, 35>>,
      <<115, 116, 97, 110, 100, 97, 114, 100, 95, 99, 111, 110, 102, 111, 114, 109, 105, 110, 103,
        95, 115, 116, 114, 105, 110, 103, 115, 0, 111, 110, 0>>,
      # parameter_status,<<"TimeZone">>,<<"Europe/Kiev">>
      <<83, 0, 0, 0, 25>>,
      <<84, 105, 109, 101, 90, 111, 110, 101, 0, 69, 117, 114, 111, 112, 101, 47, 75, 105, 101,
        118, 0>>,
      # backend_key_data,59194,2347138713
      <<75, 0, 0, 0, 12>>,
      <<0, 0, 231, 58, 139, 230, 126, 153>>,
      # ready_for_query,idle
      <<90, 0, 0, 0, 5>>,
      <<"I">>
    ]
  end

  @spec value_opts(String.t(), String.t()) :: nil | String.t()
  def value_opts(value, opts) do
    opts |> URI.decode_query() |> Map.get(value)
  end

  @spec get_external_id(String.t()) :: String.t()
  def get_external_id(username) do
    username
    |> String.split(".")
    |> List.last()
  end

  def mt(), do: System.monotonic_time(:microsecond)
end
