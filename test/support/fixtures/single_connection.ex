defmodule SingleConnection do
  alias Postgrex, as: P
  @behaviour P.SimpleConnection

  def connect(conf) do
    P.SimpleConnection.start_link(__MODULE__, [], conf)
  end

  @impl true
  def init(_args) do
    {:ok, %{from: nil}}
  end

  @impl true
  def handle_call({:query, query}, from, state) do
    {:query, query, %{state | from: from}}
  end

  def handle_result(results, state) when is_list(results) do
    P.SimpleConnection.reply(state.from, results)
    {:noreply, state}
  end

  @impl true
  def handle_result(%Postgrex.Error{} = error, state) do
    P.SimpleConnection.reply(state.from, error)
    {:noreply, state}
  end

  @impl true
  def notify(_, _, _), do: :ok
end
