defmodule Supavisor.Client do
  use GenServer
  require Logger

  def start_link(port), do: GenServer.start_link(__MODULE__, %{port: port}, name: __MODULE__)

  def send(msg) do
    GenServer.call(__MODULE__, {:send, msg})
  end

  def stop do
    GenServer.stop(__MODULE__)
  end

  @impl true
  def init(%{port: port}) do
    {:ok, sock} = :gen_tcp.connect('localhost', port, [:binary, {:active, true}])

    {:ok, %{sock: sock}}
  end

  # @impl true
  # def handle_call({:send, msg}, _from, state) do
  #   msg = :erlang.term_to_binary(msg)
  #   :gen_tcp.send(state.sock, msg)
  #   {:reply, :ok, state}
  #   # Logger.warning("Undefined message #{inspect(msg, pretty: true)}")
  #   # {:noreply, state}
  # end

  @impl true
  def handle_info({:tcp, _sock, bin}, state) do
    Logger.warning("Received #{inspect(:erlang.binary_to_term(bin))}")

    case :erlang.binary_to_term(bin) do
      {pid, bin, status} ->
        :gen_statem.cast(pid, {:client_cast, bin, status})

      other ->
        Logger.error("Unknown message: #{inspect(other)}")
    end

    {:noreply, state}
  end

  def handle_info(msg, state) do
    Logger.warning("Undefined message #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    if state.sock do
      :gen_tcp.close(state.sock)
    end

    :ok
  end
end
