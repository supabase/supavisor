defmodule SupavisorWeb.WsProxy do
  @moduledoc """
  The `Supavisor.WsProxy` module implements a WebSocket proxy for managing
  TCP connections between clients and a Postgres database.
  """

  require Logger
  @behaviour Phoenix.Socket.Transport
  @ready_for_query <<?Z, 5::32, ?I>>

  def child_spec(_opts) do
    %{
      id: Task,
      start: {Task, :start_link, [fn -> :ok end]},
      restart: :transient
    }
  end

  def connect(map), do: {:ok, map}

  def init(_) do
    proxy_port = Application.fetch_env!(:supavisor, :proxy_port)

    {:ok, socket} =
      :gen_tcp.connect('localhost', proxy_port, [:binary, packet: :raw, active: true])

    {:ok, %{status: :wait_startup, acc: "", socket: socket}}
  end

  def handle_in(
        {<<len::32, startup_pkt::binary-size(len - 4), rest::binary>>, _},
        %{status: :wait_startup} = state
      ) do
    :ok = :gen_tcp.send(state.socket, [<<len::32>>, startup_pkt])

    {:ok, %{state | acc: rest}}
  end

  def handle_in({bin, _opts}, %{socket: socket} = state) do
    :ok = :gen_tcp.send(socket, bin)
    {:ok, state}
  end

  def handle_info({:tcp, _, bin}, %{status: :wait_startup} = state) do
    if String.ends_with?(bin, @ready_for_query) do
      acc = filter_pass_pkt(state.acc)
      :ok = :gen_tcp.send(state.socket, acc)
      {:reply, :ok, {:binary, bin}, %{state | acc: nil, status: :idle}}
    else
      {:reply, :ok, {:binary, bin}, state}
    end
  end

  def handle_info({:tcp, _, bin}, %{status: :idle} = state) do
    {:reply, :ok, {:binary, bin}, state}
  end

  def handle_info(msg, state) do
    Logger.error("Undefined handle_info msg: #{inspect(msg, pretty: true)}")
    {:ok, state}
  end

  def handle_control(msg, state) do
    Logger.error("Undefined handle_control msg: #{inspect(msg, pretty: true)}")
    {:ok, state}
  end

  def terminate(_reason, _state) do
    :ok
  end

  @spec filter_pass_pkt(binary()) :: binary()
  def filter_pass_pkt(<<?p, len::32, _::binary-size(len - 4), rest::binary>>) do
    rest
  end

  def filter_pass_pkt(bin), do: bin
end
