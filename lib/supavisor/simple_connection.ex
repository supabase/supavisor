defmodule Supavisor.SimpleConnection do
  require Logger
  @behaviour Postgrex.SimpleConnection

  def connect(conf), do: Postgrex.SimpleConnection.start_link(__MODULE__, conf, conf)

  @impl true
  def init(args) do
    Logger.debug("init args: #{inspect(args, pretty: true)}")
    Process.monitor(args[:caller])
    # put the hostname in the process dictionary to be able to find it in an emergency
    Process.put(:auth_host, args[:hostname])
    {:ok, %{from: nil, caller: args[:caller]}}
  end

  @impl true
  def handle_call({:query, query}, from, state), do: {:query, query, %{state | from: from}}

  def handle_result(results, state) when is_list(results) do
    result =
      case results do
        [%Postgrex.Result{} = res] -> res
        other -> other
      end

    Postgrex.SimpleConnection.reply(state.from, result)
    {:noreply, state}
  end

  @impl true
  def handle_result(%Postgrex.Error{} = error, state) do
    Postgrex.SimpleConnection.reply(state.from, error)
    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, _, _, caller, _}, %{caller: caller} = state) do
    Logger.notice("Caller #{inspect(caller)} is down")
    {:stop, state}
  end

  def handle_info(msg, state) do
    Logger.error("Undefined message #{inspect(msg, pretty: true)}")
    {:noreply, state}
  end

  @impl true
  def notify(_, _, _), do: :ok
end
