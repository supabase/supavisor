[
  ~r(test/support/[^.]*\.ex),
  # TODO: Remove these ignores once Peep library fixes typespec in https://github.com/rkallos/peep/pull/56
  {"lib/supavisor/metrics_cleaner.ex", :no_return},
  {"lib/supavisor/metrics_cleaner.ex", :call_with_opaque},
  {"lib/supavisor/monitoring/prom_ex.ex", :no_return},
  {"lib/supavisor/monitoring/prom_ex.ex", :call_with_opaque},
  {"lib/supavisor/monitoring/prom_ex.ex", :unused_fun}
]
