defmodule Supavisor.Server do
  use GenServer
  require Logger

  def start_link(port), do: GenServer.start_link(__MODULE__, %{port: port}, name: __MODULE__)

  def send(msg) do
    GenServer.cast(__MODULE__, {:send, msg})
  end

  def stop do
    GenServer.stop(__MODULE__)
  end

  @impl true
  def init(%{port: port}) do
    {:ok, sock} = :gen_tcp.listen(port, [:binary, {:active, true}])
    # spawn(fn -> :gen_tcp.accept(sock) end)
    {:ok, %{s_sock: sock, sock: nil}, {:continue, :accept}}
  end

  @impl true
  def handle_continue(:accept, state) do
    Logger.info("Acceptting ... ")
    {:ok, client} = :gen_tcp.accept(state.s_sock)
    Logger.info("Accepted connection from #{inspect(client)}")
    {:noreply, %{state | sock: client}}
  end

  @impl true
  def handle_call({:send, msg}, _from, state) do
    Logger.info("send #{inspect(msg)}")
    msg = :erlang.term_to_binary(msg)
    :gen_tcp.send(state.sock, msg)
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:send, msg}, state) do
    Logger.info("send #{inspect(msg)}")
    msg = :erlang.term_to_binary(msg)
    :gen_tcp.send(state.sock, msg)
    {:noreply, state}
  end

  def handle_info({:tcp, _sock, bin}, state) do
    Logger.info("Received #{inspect(:erlang.binary_to_term(bin))}")
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
