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

  alias Supavisor.DbHandler, as: Db
  alias Supavisor.{Tenants, Tenants.User, Protocol.Server, Monitoring.Telem, Manager}

  @impl true
  def start_link(ref, _socket, transport, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  @impl true
  def callback_mode, do: [:handle_event_function]

  def client_call(pid, bin, ready?) do
    :gen_statem.call(pid, {:client_call, bin, ready?}, 5000)
  end

  @impl true
  def init(_), do: :ignore

  def init(ref, trans, _opts) do
    Process.flag(:trap_exit, true)

    {:ok, socket} = :ranch.handshake(ref)
    :ok = trans.setopts(socket, [{:active, true}])
    Logger.debug("ClientHandler is: #{inspect(self())}")

    data = %{
      socket: socket,
      trans: trans,
      db_pid: nil,
      tenant: nil,
      user_alias: nil,
      pool: nil,
      manager: nil,
      query_start: nil,
      mode: nil,
      timeout: nil
    }

    :gen_statem.enter_loop(__MODULE__, [hibernate_after: 5_000], :exchange, data)
  end

  @impl true
  def handle_event(:info, {:tcp, _, <<"GET", _::binary>>}, :exchange, data) do
    Logger.debug("Client is trying to request HTTP")
    :gen_tcp.send(data.socket, "HTTP/1.1 204 OK\r\n\r\n")
    {:stop, :normal, data}
  end

  def handle_event(:info, {:tcp, _, <<_::64>>}, :exchange, data) do
    Logger.warn("Client is trying to connect with SSL")
    # TODO: implement SSL negotiation
    # SSL negotiation, S/N/Error
    :gen_tcp.send(data.socket, "N")

    :keep_state_and_data
  end

  def handle_event(:info, {:tcp, _, bin}, :exchange, %{socket: socket} = data) do
    hello = decode_startup_packet(bin)
    Logger.warning("Client startup message: #{inspect(hello)}")
    {user, external_id} = parse_user_info(hello.payload["user"])
    Logger.metadata(project: external_id, user: user)

    case Tenants.get_user(external_id, user) do
      {:ok,
       %User{
         db_password: pass,
         db_user_alias: db_alias,
         mode_type: mode,
         pool_checkout_timeout: timeout
       }} ->
        {:keep_state,
         %{data | tenant: external_id, user_alias: db_alias, mode: mode, timeout: timeout},
         {:next_event, :internal, {:handle, fn -> pass end}}}

      {:error, reason} ->
        Logger.error("User not found: #{inspect(reason)} #{inspect({user, external_id})}")
        Server.send_error(socket, "XX000", "Tenant or user not found")
        {:stop, :normal, data}
    end
  end

  def handle_event(:internal, {:handle, pass}, _, %{socket: socket} = data) do
    Logger.info("Handle exchange")

    case handle_exchange(socket, pass) do
      {:error, reason} ->
        Logger.error("Exchange error: #{inspect(reason)}")

        "e=#{reason}"
        |> Server.send_exchange_message(:final, socket)

        {:stop, :normal, data}

      :ok ->
        Logger.info("Exchange success")
        :ok = :gen_tcp.send(socket, Server.authentication_ok())
        {:keep_state_and_data, {:next_event, :internal, :subscribe}}
    end
  end

  def handle_event(:internal, :subscribe, _, %{tenant: tenant, user_alias: db_alias} = data) do
    Logger.info("Subscribe to tenant #{inspect({tenant, db_alias})}")

    with {:ok, tenant_sup} <- Supavisor.start(tenant, db_alias),
         {:ok, %{manager: manager, pool: pool}} <-
           Supavisor.subscribe_global(node(tenant_sup), self(), tenant, db_alias),
         ps <-
           Manager.get_parameter_status(manager) do
      data = %{data | pool: pool}
      db_pid = db_checkout(data)

      Process.monitor(manager)
      data = %{data | manager: manager, db_pid: db_pid}

      if ps == [] do
        {:keep_state, data, {:timeout, 10_000, :wait_ps}}
      else
        {:keep_state, data, {:next_event, :internal, {:greetings, ps}}}
      end
    else
      error ->
        Logger.error("Subscribe error: #{inspect(error)}")
        {:keep_state_and_data, {:timeout, 1000, :subscribe}}
    end
  end

  def handle_event(:internal, {:greetings, ps}, _, data) do
    :ok = :gen_tcp.send(data.socket, Server.greetings(ps))
    {:next_state, :idle, data}
  end

  def handle_event(:timeout, :subscribe, _, _) do
    {:keep_state_and_data, {:next_event, :internal, :subscribe}}
  end

  def handle_event(:timeout, :wait_ps, _, _) do
    Logger.error("Wait parameter status timeout")
    ps = Server.stub_ps()
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  # ignore termination messages
  def handle_event(:info, {:tcp, _, <<?X, 4::32>>}, _, _) do
    Logger.warn("Receive termination")
    :keep_state_and_data
  end

  def handle_event(:info, {:tcp, _, bin}, :idle, data) do
    ts = System.monotonic_time()
    db_pid = db_checkout(data)

    {:next_state, :busy, %{data | db_pid: db_pid, query_start: ts},
     {:next_event, :internal, {:tcp, nil, bin}}}
  end

  def handle_event(_, {:tcp, _, bin}, :busy, data) do
    case Db.call(data.db_pid, bin) do
      :ok ->
        Logger.info("DB call success")
        :keep_state_and_data

      {:buffering, size} ->
        Logger.warn("DB call buffering #{size}}")

        if size > 1_000_000 do
          msg = "Db buffer size is too big: #{size}"
          Logger.error(msg)
          Server.send_error(data.socket, "XX000", msg)
          {:stop, :normal, data}
        else
          Logger.debug("DB call buffering")
          :keep_state_and_data
        end

      {:error, reason} ->
        msg = "DB call error: #{inspect(reason)}"
        Logger.error(msg)
        Server.send_error(data.socket, "XX000", msg)
        {:stop, :normal, data}
    end
  end

  def handle_event(:info, {:parameter_status, ps}, _, _) do
    {:keep_state_and_data, {:next_event, :internal, {:greetings, ps}}}
  end

  # client closed connection
  def handle_event(_, {:tcp_closed, _}, _, data) do
    Logger.info("tcp soket closed for #{inspect(data.tenant)}")
    {:stop, :normal}
  end

  # linked db_handler went down
  def handle_event(:info, {:EXIT, db_pid, reason}, _, _) do
    Logger.error("DB handler #{inspect(db_pid)} exited #{inspect(reason)}")
    {:stop, :normal}
  end

  # pool's manager went down
  def handle_event(:info, {:DOWN, _, _, _, reason}, state, data) do
    Logger.error(
      "Manager #{inspect(data.manager)} went down #{inspect(reason)} state #{inspect(state)}"
    )

    case state do
      :idle ->
        {:keep_state_and_data, {:next_event, :internal, :subscribe}}

      :busy ->
        {:stop, :normal}
    end
  end

  # emulate handle_call
  def handle_event({:call, from}, {:client_call, bin, ready?}, _, data) do
    Logger.debug("--> --> bin #{inspect(byte_size(bin))} bytes")

    reply = {:reply, from, :gen_tcp.send(data.socket, bin)}

    if ready? do
      Logger.debug("Client is ready")

      db_pid = handle_db_pid(data.mode, data.pool, data.db_pid)

      Telem.network_usage(:client, data.socket, data.tenant, data.user_alias)
      Telem.client_query_time(data.query_start, data.tenant, data.user_alias)
      {:next_state, :idle, %{data | db_pid: db_pid}, reply}
    else
      Logger.debug("Client is not ready")
      {:keep_state_and_data, reply}
    end
  end

  def handle_event(type, content, state, data) do
    msg = [
      {"type", type},
      {"content", content},
      {"state", state},
      {"data", data}
    ]

    Logger.debug("Undefined msg: #{inspect(msg, pretty: true)}")

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
          "Too many clients already"

        :transaction ->
          "Unable to check out process from the pool due to timeout"
      end

    Logger.error(msg)
    Server.send_error(data.socket, "XX000", msg)
    :ok
  end

  def terminate(_reason, _state, _data), do: :ok

  ## Internal functions

  @spec parse_user_info(String.t()) :: {String.t() | nil, String.t()}
  def parse_user_info(username) do
    case :binary.matches(username, ".") do
      [] ->
        {nil, username}

      matches ->
        {pos, _} = List.last(matches)
        {name, "." <> external_id} = String.split_at(username, pos)
        {name, external_id}
    end
  end

  def decode_startup_packet(<<len::integer-32, _protocol::binary-4, rest::binary>>) do
    %{
      len: len,
      payload:
        String.split(rest, <<0>>, trim: true)
        |> Enum.chunk_every(2)
        |> Enum.into(%{}, fn [k, v] -> {k, v} end),
      tag: :startup
    }
  end

  def decode_startup_packet(_) do
    :undef
  end

  @spec handle_exchange(port, fun) :: :ok | {:error, String.t()}
  def handle_exchange(socket, password) do
    :ok = Server.send_request_authentication(socket)

    receive do
      {:tcp, socket, bin} ->
        case Server.decode_pkt(bin) do
          {:ok,
           %{tag: :password_message, payload: {:scram_sha_256, %{"n" => user, "r" => nonce}}},
           _} ->
            message = Server.exchange_first_message(nonce)
            server_first_parts = :pgo_scram.parse_server_first(message, nonce)

            {client_final_message, server_proof} =
              :pgo_scram.get_client_final(
                server_first_parts,
                nonce,
                user,
                password.()
              )

            :ok =
              message
              |> Server.send_exchange_message(:first, socket)

            receive do
              {:tcp, socket, bin} ->
                case Server.decode_pkt(bin) do
                  {:ok, %{tag: :password_message, payload: {:first_msg_response, %{"p" => p}}}, _} ->
                    if p == List.last(client_final_message) do
                      "v=#{Base.encode64(server_proof)}"
                      |> Server.send_exchange_message(:final, socket)
                    else
                      {:error, "Invalid client signature"}
                    end

                  other ->
                    {:error, "Unexpected message #{inspect(other)}"}
                end

              other ->
                {:error, "Unexpected message #{inspect(other)}"}
            after
              15_000 ->
                {:error, "Timeout while waiting for the second password message"}
            end

          other ->
            {:error, "Unexpected message #{inspect(other)}"}
        end
    after
      15_000 ->
        {:error, "Timeout while waiting for the first password message"}
    end
  end

  @spec db_checkout(map()) :: pid()
  defp db_checkout(%{mode: :session, db_pid: db_pid}) when is_pid(db_pid) do
    db_pid
  end

  defp db_checkout(data) do
    {time, db_pid} = :timer.tc(:poolboy, :checkout, [data.pool, true, data.timeout])
    Process.link(db_pid)
    Telem.pool_checkout_time(time, data.tenant, data.user_alias)
    db_pid
  end

  @spec handle_db_pid(:transaction, pid(), pid()) :: nil
  @spec handle_db_pid(:session, pid(), pid()) :: pid()
  defp handle_db_pid(:transaction, pool, db_pid) do
    Process.unlink(db_pid)
    :poolboy.checkin(pool, db_pid)
    nil
  end

  defp handle_db_pid(:session, _, db_pid), do: db_pid
end
