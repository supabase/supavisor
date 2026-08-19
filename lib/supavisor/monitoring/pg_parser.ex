defmodule Supavisor.PromEx.Plugins.PgParser do
  @moduledoc """
  Polls the `Supavisor.PgParser` per-scheduler parse shape cache counters.

  Both counters are cumulative since VM start and exported as `last_value`
  (use `rate()` in PromQL). The cache is a global NIF-level structure, so
  these metrics intentionally carry no tenant tags.
  """

  use PromEx.Plugin

  @event [:supavisor, :pg_parser, :cache, :stats]
  @prefix [:parser_cache]

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate)

    [
      Polling.build(
        :supavisor_pg_parser_events,
        poll_rate,
        {Supavisor.Monitoring.Telem, :execute_parser_cache_stats, []},
        [
          last_value(@prefix ++ [:hits],
            event_name: @event,
            description: "Parse cache hits (shape key found, no parse needed).",
            measurement: :hits
          ),
          last_value(@prefix ++ [:misses],
            event_name: @event,
            description: "Parse cache misses (eligible shape, not yet cached).",
            measurement: :misses
          )
        ]
      )
    ]
  end
end
