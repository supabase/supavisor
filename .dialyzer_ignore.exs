[
  ~r(test/support/[^.]*\.ex),
  # :syn.join/4's PLT-derived type is `:ok` only (an upstream spec bug in
  # deps/syn/src/syn_pg.erl), but it genuinely returns {:error, :not_alive}
  # for a dead pid at runtime - see Supavisor.join_tenant_pool/2.
  {"lib/supavisor.ex", "The pattern can never match the type :ok."},
  # :ssl_gen_statem.socket_control/5 specs its trackers as [pid()] | atom(), but
  # ssl itself passes [{:session_id_tracker, pid | :not_relevant}], as
  # Supavisor.TLSHandshake (ported from tls_gen_connection) does.
  {"lib/supavisor/tls_handshake.ex", "The function call socket_control will not succeed."},
  {"lib/supavisor/tls_handshake.ex", "Function socket_control/6 has no local return."}
]
