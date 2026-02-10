defmodule Supavisor.ErlSysMon do
  @moduledoc """
  Logs Erlang System Monitor events.

  For better processes identification, they can be labeled using `:proc_lib.set_label/1`.
  If a message contains a pid with a label, the label will be included in the log
  for easier debugging and monitoring.
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
    enriched_msg = maybe_enrich_message(msg)
    Logger.warning("#{__MODULE__} message: " <> inspect(enriched_msg))
    {:noreply, state}
  end

  defp maybe_enrich_message({:monitor, pid, _type, _info} = msg) when is_pid(pid) do
    case :proc_lib.get_label(pid) do
      :undefined -> msg
      label -> {msg, proc_label: label}
    end
  end

  defp maybe_enrich_message(msg), do: msg
end
