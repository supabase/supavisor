[
  ~r(test/support/[^.]*\.ex),
  # Defensive 2-tuple clause kept for relup compatibility with v2.9.6 nodes
  # whose Helpers.get_client_final/5 returned a 2-tuple. Remove with the TODO.
  ~r{^lib/supavisor/db_handler\.ex:822:\d+:pattern_match\b}
]
