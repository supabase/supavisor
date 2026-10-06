defmodule Supavisor.PromEx.Plugins.MessageQueue do
  @moduledoc """
  Polls message queue lengths of relevant singleton processes.
  """

  use PromEx.Plugin

  alias Supavisor.MessageQueueWatchdog

  @event [:supavisor, :prom_ex, :process]

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      Polling.build(
        :supavisor_message_queue_events,
        poll_rate,
        {__MODULE__, :execute_metrics, []},
        [
          last_value(
            @event ++ [:message_queue_len],
            event_name: @event,
            description: "The number of messages in the process mailbox.",
            measurement: :message_queue_len,
            tags: [:name]
          )
        ]
      )
    ]
  end

  @spec execute_metrics() :: :ok
  def execute_metrics do
    Enum.each(MessageQueueWatchdog.queue_lengths(), fn {name, len} ->
      :telemetry.execute(@event, %{message_queue_len: len}, %{name: name})
    end)
  end
end
