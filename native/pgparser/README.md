# pgparser — SQL classification NIF with per-scheduler parse shape cache

C NIF backing `Supavisor.PgParser`. Classifies SQL statements for the
simple-query path (`statement_types/1`, contract unchanged:
`{:ok, ["SelectStmt", ...]} | {:error, "Error parsing query"}`) and caches
parse results keyed by statement *shape* to skip re-parsing.

Replaced the former Rustler/`pg_query.rs` NIF: no protobuf AST is built or
crossed over the NIF boundary anymore; classification walks the raw parse
tree directly in C.

## Background

Every query that arrives over the PostgreSQL simple protocol is classified
before routing (`Supavisor.PgParser.statement_types/1`), so classification
is one of the hottest data-plane paths. The previous implementation parsed
every SQL string from scratch through a Rustler crate that built a full
protobuf AST and decoded it into Rust structs — even though the result
depends only on the statement *shape*. This NIF removes both costs: a raw
parse in C (no protobuf, no Rust toolchain), plus a per-scheduler cache
keyed by shape so a hit never parses at all.

## Layout

- `Makefile` — build chain: download pinned libpg_query tarball (sha256
  verified) → apply `patches/*.patch` if any (currently none; internal
  headers shipped in the tarball are sufficient) → `make build` libpg_query →
  generate `c_src/pg_nodetags.inc` from `nodetags.h` → link
  `priv/native/pgparser.so`.
- `c_src/pg_nif.c` — NIF boundary: TSD per-scheduler caches, stats
  aggregation (`cache_stats/0`), hot-upgrade handling.
- `c_src/pg_parse_info.{h,c}` — `pg_parse_info_t` (QueryInfo: statement
  count + NodeTag array) extracted from `pg_query_raw_parse` output.
  Bump `PG_PARSE_INFO_RULES_VERSION` whenever extraction rules change.
- `c_src/pg_shape.{h,c}` — ShapeKey: streams the PostgreSQL core scanner
  and encodes a canonical token stream (keywords → token codes,
  identifiers/operators → normalized bytes, `$n` → param number, literal
  values folded to their type tag, comments/whitespace skipped, trailing
  semicolons ignored). Multi-statement input, leading keywords outside
  {SELECT, INSERT, UPDATE, DELETE, MERGE}, parse-time-validated literals
  (unicode literals and float(p) precisions), and scanner errors bypass
  the cache and always parse.
- `c_src/pg_hash_sink.{h,c}` — stable big-endian record writes + seeded
  XXH64 incremental hashing (seed folded from random per-boot material;
  best-effort poisoning resistance, not cryptographic).
- `c_src/pg_cache.{h,c}` — per-scheduler lock-free LRU + global registry
  for stats.
- `c_src/xxh64.h` — XXH64 streaming hash, header-only verbatim extraction
  from xxHash v0.8.3 (BSD 2-Clause), pinned by upstream sanity vectors.
- `test/shape_cache_tests.c` — C unit tests (103 checks): shape equivalence
  classes, XXH64 known-answer + streaming consistency, LRU semantics, stats
  identities.

## Build

```bash
mix compile                              # via elixir_make (make -C native/pgparser)
make -C native/pgparser test             # C unit tests
LIBPG_QUERY_TARBALL=/path/to.tgz make -C native/pgparser   # offline/nix
```

Dependencies: `cc`, `make`, `curl` (or a pre-seeded tarball). No Rust
toolchain is involved. `vendor/`, `*.o`, and `c_src/pg_nodetags.inc` are
build artifacts (gitignored).

## Cache model

```
simple query
    │
    ▼
scan once with the PostgreSQL core scanner
    │
    ├─ not eligible (non-DML, multi-statement, scan error)
    │    └─► full C parse ──► result                         [bypass]
    │
    └─ eligible ──► per-scheduler LRU lookup
                      ├─ hit  ──► cached result
                      └─ miss ──► full C parse ──► insert ──► result
```

`PARSER_CACHE_SIZE` (default 1024, `0` disables) bounds each scheduler's
LRU. Hit path = scan only (no parse, no AST): the scanner is the shared
irreducible cost. Miss path additionally runs one raw parse and inserts only
when the AST confirms a single allowlisted statement, so cached results can
never diverge from parse results. Memory ≈ `size × ~300 bytes × schedulers`.

## Correctness

The cache must never return a result the parser itself would not have
returned. Five mechanisms enforce this:

1. **Conservative eligibility** — only single-statement
   SELECT/INSERT/UPDATE/DELETE/MERGE queries are eligible; everything else
   bypasses to a full parse with identical semantics.
2. **Same key ⇒ same result** — the shape encoding folds only aspects that
   provably cannot change the top-level statement kinds (literal values per
   literal type, whitespace, comments, trailing semicolons); keywords,
   identifiers, operators and parameter numbers all join the key.
3. **Every insert is gated by a real parse** — an entry is written only
   after a full raw parse of that very SQL confirms one allowlisted
   statement; lookups compare the full key (64-bit XXH64 digest + token
   count + serialized size).
4. **Versioned context header** — every key includes a magic, a format
   version and `PG_PARSE_INFO_RULES_VERSION`, so rule changes retire old
   keys by LRU pressure after a hot upgrade.
5. **ABI-checked state reuse** — hot upgrade reuses native state only when
   a magic plus `PG_NIF_STATE_ABI_VERSION` prove layout compatibility.

## Performance

Measured on an Alibaba Cloud `ecs.c9i.2xlarge` spot instance
(Linux x86_64, 8 cores, Intel Xeon 6982P-C, Elixir 1.18.2 / OTP 27.2,
`PARSER_CACHE_SIZE=0` for the C-parse column, default cache for the
hit column, `mix run --no-start bench/pg_parser.exs`, 2026-08-03).
The Rust protobuf baseline is the original aarch64 measurement and is
left unchanged for comparison.

| workload | Rust protobuf (old) | C parse (no cache) | cache hit |
| --- | --- | --- | --- |
| trivial select | 4.35 µs | 0.87 µs | 0.59 µs |
| analytical select (joins + windows) | 100.87 µs | 9.93 µs | 5.43 µs |
| long IN list (~1.2 KB) | 176.85 µs | 13.14 µs | 5.96 µs |

Cache miss costs one scan + one parse (~1.64 µs trivial); bypass adds one
scan (~0.98 µs trivial) and behaves exactly like the no-cache path.

## Hot upgrade semantics

- `upgrade/3` reuses the old instance's `priv_data`: TSD key, all caches and
  the hash secret survive a code reload; the old library's `unload` receives
  `NULL` and does nothing.
- Any change to classification/shape rules must bump
  `PG_PARSE_INFO_RULES_VERSION`: it is part of every shape key's context
  header, so keys written by the old rules simply miss after the upgrade and
  age out via LRU — no stale results, no explicit flush.
- A new `PARSER_CACHE_SIZE` picked up during upgrade applies to per-scheduler
  caches created afterwards; existing caches keep their original bound.
- `enif_tsd` has no destructor callback: caches of schedulers that went away
  are reclaimed only at NIF unload (bounded by schedulers × entries × ~300
  bytes).

## Observability

`cache_stats/0` returns the aggregated counters; the two headline counters
are exported as `parser_cache_hits` / `parser_cache_misses` Prometheus
metrics (see `docs/monitoring/metrics.md`).
