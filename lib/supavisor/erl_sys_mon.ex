defmodule Supavisor.ErlSysMon do
  @moduledoc """
  Logs Erlang System Monitor events.
  """

  use GenServer
  alias Supavisor.Helpers

  require Logger

  def start_link(args) do
    name = args[:name] || __MODULE__
    GenServer.start_link(__MODULE__, args, name: name)
  end

  def init(_args) do
    :erlang.system_monitor(self(), [
      :busy_dist_port,
      :busy_port,
      {:long_gc, 250},
      {:long_schedule, 100},
      {:long_message_queue, {0, 1_000}},
      {:large_heap, Helpers.mb_to_words(25)}
    ])

    {:ok, []}
  end

  def handle_info(msg, state) do
    Logger.warning("#{__MODULE__} message: " <> inspect(msg))

    {:noreply, state}
  end
end
