defmodule SupavisorWeb.WsProxy do
  @moduledoc """
  The `Supavisor.WsProxy` module implements a WebSocket proxy for managing
  TCP connections between clients and a Postgres database.
  """

  require Logger
  alias Supavisor.Protocol.Client
  alias Supavisor.Protocol.Server
  alias Supavisor.Protocol.StartupOptions
  @behaviour Plug

  def call(conn, state) do
    Logger.debug("WsProxy is: #{inspect(self())}")
    state = %{state | client_ip: conn.remote_ip |> :inet.ntoa() |> to_string()}
    Plug.Conn.upgrade_adapter(conn, :websocket, {__MODULE__, state, %{compress: false}})
  end

  def init(_) do
    %{socket: nil, acc: nil, status: :startup, client_ip: nil}
  end

  def websocket_handle(
        {:binary, <<len::32, startup_pkt::binary-size(len - 4), rest::binary>>},
        %{status: :startup} = state
      ) do
    {port, startup_pkt} = local_startup(<<len::32, startup_pkt::binary>>, state.client_ip)
    {:ok, socket} = :gen_tcp.connect(~c"localhost", port, [:binary, packet: :raw, active: true])
    :ok = :gen_tcp.send(socket, startup_pkt)

    {:ok, %{state | acc: rest, socket: socket}}
  end

  def websocket_handle({:binary, bin}, %{socket: socket} = state) do
    :ok = :gen_tcp.send(socket, bin)
    {:ok, state}
  end

  def websocket_info({:tcp, _, bin}, %{status: :startup} = state) do
    if String.ends_with?(bin, Server.ready_for_query()) do
      acc = filter_pass_pkt(state.acc)
      :ok = :gen_tcp.send(state.socket, acc)
      {[{:binary, bin}], %{state | acc: nil, status: :idle}}
    else
      {[{:binary, bin}], state}
    end
  end

  def websocket_info({:tcp, _, bin}, %{status: :idle} = state) do
    {[{:binary, bin}], state}
  end

  def websocket_info({:tcp_closed, socket}, %{socket: socket}) do
    {:stop, :normal}
  end

  def websocket_info(msg, state) do
    Logger.error("Undefined websocket_info msg: #{inspect(msg, pretty: true)}")
    {:ok, state}
  end

  @spec filter_pass_pkt(binary()) :: binary()
  def filter_pass_pkt(<<?p, len::32, _::binary-size(len - 4), rest::binary>>) do
    rest
  end

  def filter_pass_pkt(bin), do: bin

  # Adds the client's IP and TLS status to the startup message.
  defp local_startup(<<_len::32, protocol::binary-4, _::binary>> = packet, client_ip) do
    case Client.decode_startup_packet(packet) do
      {:ok, %{payload: payload}} ->
        options =
          payload
          |> Map.get("options", %{})
          |> Map.merge(%{
            "client_ip" => client_ip,
            # HTTPS is enforced at the infra layer, so clients always use TLS.
            "client_tls" => "true"
          })

        params =
          payload
          |> Map.put("options", StartupOptions.encode(options))
          |> Enum.map(fn {key, value} -> [key, 0, value, 0] end)

        body = IO.iodata_to_binary([protocol, params, 0])

        {internal_port({payload["user"], payload["database"]}),
         [<<byte_size(body) + 4::32>>, body]}

      # Not a startup message.
      {:error, _} ->
        {internal_port(nil), packet}
    end
  end

  defp internal_port(key) do
    ports = Application.fetch_env!(:supavisor, :transaction_proxy_ports)
    :ranch.get_port({:pg_proxy_internal, :transaction, :erlang.phash2(key, length(ports))})
  end
end
