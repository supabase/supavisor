defmodule Supavisor.PromEx.Plugins.LoggerLines do
  @moduledoc "This module defines the PromEx plugin for logger burst-limit overload metrics."

  use PromEx.Plugin

  @impl true
  def event_metrics(_opts) do
    Event.build(
      :supavisor_logger_lines_event_metrics,
      [
        sum(
          [:supavisor, :logger, :lines, :total],
          event_name: [:supavisor, :logger, :lines],
          measurement: :count,
          description: "Total number of log events reaching the logger's :default handler."
        ),
        sum(
          [:supavisor, :logger, :burst_limit, :dropped, :total],
          event_name: [:supavisor, :logger, :burst_limit, :dropped],
          measurement: :count,
          description:
            "Estimated number of log events dropped by the logger's burst-limit overload protection."
        )
      ]
    )
  end
end
