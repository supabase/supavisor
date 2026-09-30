[
  ~r(test/support/[^.]*\.ex),
  # :syn.join/3's PLT-derived type is `:ok` only (an upstream spec bug in
  # deps/syn/src/syn_pg.erl), but it genuinely returns {:error, :not_alive}
  # for a dead pid at runtime - see Supavisor.join_tenant_pool/3.
  {"lib/supavisor.ex", "The pattern can never match the type :ok."}
]
