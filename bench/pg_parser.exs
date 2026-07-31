alias Supavisor.PgParser, as: Parser

analytical_select = """
SELECT
  o.order_id,
  c.customer_name,
  SUM(oi.quantity * oi.unit_price) AS total_amount,
  ROW_NUMBER() OVER (PARTITION BY c.region ORDER BY SUM(oi.quantity * oi.unit_price) DESC) AS region_rank,
  AVG(oi.unit_price) OVER (ORDER BY o.order_date ROWS BETWEEN 3 PRECEDING AND CURRENT ROW) AS moving_avg
FROM orders o
JOIN customers c ON c.customer_id = o.customer_id AND c.status = 'active'
LEFT JOIN order_items oi ON oi.order_id = o.order_id
JOIN products p ON p.product_id = oi.product_id AND p.category_id IN (1, 2, 3)
WHERE o.order_date BETWEEN '2024-01-01' AND '2024-12-31'
  AND o.status NOT IN ('cancelled', 'refunded')
GROUP BY o.order_id, c.customer_name, c.region, o.order_date
HAVING SUM(oi.quantity) > 10
ORDER BY total_amount DESC NULLS LAST
LIMIT 100 OFFSET 20
"""

cte_chain = """
WITH regional_sales AS (
  SELECT region, SUM(amount) AS total
  FROM sales
  WHERE sale_date >= DATE '2024-01-01'
  GROUP BY region
),
top_regions AS (
  SELECT region FROM regional_sales
  WHERE total > (SELECT AVG(total) * 1.5 FROM regional_sales)
),
ranked_products AS (
  SELECT p.product_id, p.name, s.region,
         RANK() OVER (PARTITION BY s.region ORDER BY SUM(s.amount) DESC) AS rnk
  FROM sales s JOIN products p ON p.product_id = s.product_id
  WHERE s.region IN (SELECT region FROM top_regions)
  GROUP BY p.product_id, p.name, s.region
)
SELECT r.region, r.name, r.rnk, t.total
FROM ranked_products r JOIN regional_sales t ON t.region = r.region
WHERE r.rnk <= 5
ORDER BY r.region, r.rnk
"""

insert_multi_row = """
INSERT INTO inventory.stock_log (product_id, warehouse_id, quantity_change, reason, recorded_by, metadata)
VALUES
  (101, 'W1', 50, 'restock', 'system', '{"source": "po-1001"}'),
  (102, 'W1', -3, 'damage', 'user-42', '{"photos": ["a.jpg", "b.jpg"]}'),
  (103, 'W2', 200, 'restock', 'system', '{"source": "po-1002"}'),
  (104, 'W2', 0, 'audit', 'user-7', '{}'),
  (105, 'W1', 12, 'return', 'user-99', '{"rma": "R123"}')
ON CONFLICT (product_id, warehouse_id, log_time)
DO UPDATE SET quantity_change = EXCLUDED.quantity_change + inventory.stock_log.quantity_change
RETURNING log_id, product_id, quantity_change
"""

update_with_subquery = """
UPDATE employees e
SET salary = e.salary * 1.1,
    last_reviewed = NOW()
FROM departments d
WHERE e.department_id = d.department_id
  AND d.budget_year = 2024
  AND e.performance_score >= (
    SELECT AVG(performance_score) + STDDEV(performance_score)
    FROM employees
    WHERE department_id = d.department_id
  )
  AND EXISTS (
    SELECT 1 FROM projects p
    WHERE p.lead_id = e.employee_id AND p.status = 'active'
  )
RETURNING e.employee_id, e.salary
"""

merge_stmt = """
MERGE INTO target_inventory t
USING source_updates s ON t.product_id = s.product_id AND t.warehouse_id = s.warehouse_id
WHEN MATCHED AND s.quantity = 0 THEN
  DELETE
WHEN MATCHED THEN
  UPDATE SET quantity = s.quantity, updated_at = NOW()
WHEN NOT MATCHED AND s.quantity > 0 THEN
  INSERT (product_id, warehouse_id, quantity, updated_at)
  VALUES (s.product_id, s.warehouse_id, s.quantity, NOW())
"""

jsonb_array = """
SELECT
  o.id,
  o.payload -> 'customer' ->> 'email' AS email,
  jsonb_path_query_array(o.payload, '$.items[*].price') AS prices,
  ARRAY(SELECT jsonb_array_elements_text(o.payload -> 'tags')) AS tags
FROM orders_json o
WHERE o.payload @> '{"status": "shipped"}'
  AND o.payload ? 'tracking_number'
  AND jsonb_path_exists(o.payload, '$.items[*] ? (@.price > 100)')
  AND cardinality(ARRAY(SELECT jsonb_object_keys(o.payload))) > 3
ORDER BY o.payload ->> 'created_at' DESC
"""

nested_subquery = """
SELECT * FROM t1
WHERE a = (SELECT MAX(x) FROM t2 WHERE t2.b = t1.a)
  AND b IN (SELECT c FROM t3 WHERE d IN (SELECT e FROM t4 WHERE f IN (SELECT g FROM t5)))
  AND ((t1.h > 10 AND (t1.i < 20 OR (t1.j = 5 AND (t1.k IS NOT NULL OR t1.l BETWEEN 1 AND 100))))
       OR (t1.m IN (SELECT n FROM t6 WHERE (t6.o || t6.p) LIKE '%x%' AND (t6.q::int & 4) = 4)))
  AND NOT (t1.r AND (t1.s OR (t1.t AND (t1.u OR NOT t1.v))))
"""

long_in_list =
  "SELECT * FROM large_table WHERE id IN (" <>
    Enum.map_join(1..200, ", ", &Integer.to_string/1) <>
    ") AND status IN ('a', 'b', 'c', 'd', 'e') AND created_at > '2024-01-01'"

multi_statement = """
SELECT 1;
INSERT INTO audit_log (event) VALUES ('multi');
UPDATE counters SET value = value + 1 WHERE name = 'hits'
"""

do_block = """
DO $$
DECLARE
  v_count integer;
BEGIN
  SELECT COUNT(*) INTO v_count FROM events WHERE processed = false;
  IF v_count > 1000 THEN
    RAISE NOTICE 'backlog: %', v_count;
  END IF;
END $$
"""

Benchee.run(%{
  "statement_types/1" => fn ->
    Parser.statement_types("insert into table1 values ('a', 'b')")
  end,
  "statement_types/1 analytical select (joins + windows)" => fn ->
    Parser.statement_types(analytical_select)
  end,
  "statement_types/1 cte chain" => fn ->
    Parser.statement_types(cte_chain)
  end,
  "statement_types/1 insert multi-row returning" => fn ->
    Parser.statement_types(insert_multi_row)
  end,
  "statement_types/1 update with subquery" => fn ->
    Parser.statement_types(update_with_subquery)
  end,
  "statement_types/1 merge" => fn ->
    Parser.statement_types(merge_stmt)
  end,
  "statement_types/1 jsonb + arrays" => fn ->
    Parser.statement_types(jsonb_array)
  end,
  "statement_types/1 deeply nested subquery" => fn ->
    Parser.statement_types(nested_subquery)
  end,
  "statement_types/1 long IN list (~1.2KB)" => fn ->
    Parser.statement_types(long_in_list)
  end,
  "statement_types/1 multi-statement" => fn ->
    Parser.statement_types(multi_statement)
  end,
  "statement_types/1 dollar-quoted DO block" => fn ->
    Parser.statement_types(do_block)
  end
})

# Baseline (Rust pg_query.rs 6.1.0, protobuf AST), Linux 10 cores, Elixir 1.18.2 / OTP 27.2,
# mix run --no-start bench/pg_parser.exs, 2026-07-30:
#
# Name                                                            ips        average
# statement_types/1 dollar-quoted DO block                   349.01 K        2.87 μs
# statement_types/1 (trivial insert)                         229.77 K        4.35 μs
# statement_types/1 multi-statement                           60.95 K       16.41 μs
# statement_types/1 merge                                     23.81 K       41.99 μs
# statement_types/1 insert multi-row returning                20.41 K       48.99 μs
# statement_types/1 jsonb + arrays                            17.67 K       56.60 μs
# statement_types/1 update with subquery                      16.01 K       62.45 μs
# statement_types/1 analytical select (joins + windows)        9.91 K      100.87 μs
# statement_types/1 cte chain                                  9.65 K      103.59 μs
# statement_types/1 deeply nested subquery                     9.64 K      103.72 μs
# statement_types/1 long IN list (~1.2KB)                      5.65 K      176.85 μs

# Phase 1 (C NIF directly linked against libpg_query 17-6.2.1, raw parse without
# protobuf), same machine 2026-07-30:
#
# Name                                                            ips        average
# statement_types/1 (trivial insert)                        1822.49 K        0.55 μs
# statement_types/1 dollar-quoted DO block                  1548.43 K        0.65 μs
# statement_types/1 multi-statement                          814.79 K        1.23 μs
# statement_types/1 merge                                    322.86 K        3.10 μs
# statement_types/1 update with subquery                     269.69 K        3.71 μs
# statement_types/1 jsonb + arrays                           260.51 K        3.84 μs
# statement_types/1 insert multi-row returning               254.22 K        3.93 μs
# statement_types/1 deeply nested subquery                   175.48 K        5.70 μs
# statement_types/1 analytical select (joins + windows)      149.95 K        6.67 μs
# statement_types/1 cte chain                                146.12 K        6.84 μs
# statement_types/1 long IN list (~1.2KB)                    110.37 K        9.06 μs

# --- Phase 2: per-scheduler shape cache comparison (appended block; the
# original blocks above are unchanged) ---
hit_sql = "SELECT * FROM t WHERE id = 1"
hit_variants = List.to_tuple(for n <- 1..10, do: "SELECT * FROM t WHERE id = #{n}")
miss_counter = :counters.new(1, [])
variant_counter = :counters.new(1, [])

Benchee.run(%{
  "cache hit (repeated same SQL)" => fn ->
    Parser.statement_types(hit_sql)
  end,
  "cache hit (varying literals, same shape)" => fn ->
    n = :counters.get(variant_counter, 1)
    :counters.add(variant_counter, 1, 1)
    Parser.statement_types(elem(hit_variants, rem(n, 10)))
  end,
  "cache miss (unique shape each call)" => fn ->
    n = :counters.get(miss_counter, 1)
    :counters.add(miss_counter, 1, 1)
    Parser.statement_types("SELECT * FROM bench_t_#{n} WHERE id = 1")
  end,
  "cache hit analytical select (joins + windows)" => fn ->
    Parser.statement_types(analytical_select)
  end,
  "cache hit long IN list (~1.2KB)" => fn ->
    Parser.statement_types(long_in_list)
  end,
  "cache bypass (PREPARE)" => fn ->
    Parser.statement_types("PREPARE stmt AS SELECT $1")
  end
})

# Phase 2 (per-scheduler shape cache, hit path with per-token encoding inlined),
# same machine 2026-07-30:
# (this file was first run once with the cache disabled for the Phase 1 scenario
# block, then this block; the numbers below are the hit path)
#
# Name                                                    ips        average
# cache hit (varying literals, same shape)             2.12 M        0.47 μs
# cache hit (repeated same SQL)                        2.09 M        0.48 μs
# cache bypass (PREPARE)                               1.59 M        0.63 μs
# cache miss (unique shape each call)                  0.92 M        1.09 μs
# cache hit analytical select (joins + windows)       0.196 M        5.11 μs
# cache hit long IN list (~1.2KB)                     0.170 M        5.89 μs
#
# Reading the numbers: trivial-SQL hits are ~9x the protobuf baseline; complex
# SQL hits are ~17-30x the baseline, and a hit (scan only, building the shape
# key) is already faster than a direct C parse (analytical 6.67 μs, long IN
# 9.06 μs). Hit path cost = scanner pass (the irreducible cost shared with
# parsing) + shape encoding + LRU lookup (~2ns, see the C micro-benchmarks).

# --- Phase 3: shape hash swap, keyed BLAKE3-256 -> seeded XXH64 (appended
# block; the blocks above are unchanged) ---
# Same machine (Linux aarch64, 10 cores, Elixir 1.18.2 / OTP 27.2), both
# builds run back-to-back on 2026-08-03 with the default cache enabled;
# averages in µs. Phase 1 rows with an eligible statement are cache hits
# after the first call; multi-statement / DO block / CTE chain bypass the
# cache (scan + parse) and are hash-independent — they double as the
# environment sanity check.
#
# Phase 1 (repeated same SQL):
# workload                     BLAKE3   XXH64    delta
# trivial insert               0.53     0.44     -17%
# analytical select            5.44     4.32     -21%
# long IN list (~1.2KB)        6.30     4.92     -22%
# merge                        2.93     2.13     -27%
# jsonb + arrays               2.82     2.30     -18%
# update with subquery         2.93     2.34     -20%
# insert multi-row returning   3.25     2.57     -21%
# deeply nested subquery       4.12     3.40     -17%
# dollar-quoted DO (bypass)    0.82     0.79     ~noise
# multi-statement (bypass)     1.41     1.43     ~noise
# cte chain (bypass)           7.39     7.18     ~noise
#
# Phase 2 (dedicated cache scenarios):
# scenario                     BLAKE3   XXH64    delta
# cache hit (repeated)         0.48     0.41     -15% (ips 2.08M -> 2.45M, +18%)
# cache hit (varying literals) 0.49     0.41     -16% (ips 2.04M -> 2.43M, +19%)
# cache hit analytical         5.33     4.43     -17%
# cache hit long IN (~1.2KB)   6.21     4.93     -21% (ips 0.161M -> 0.20M, +24%)
# cache miss (scan + parse)    1.09     1.06     ~noise
# bypass (PREPARE)             0.64     0.67     ~noise
#
# Reading the numbers: gains are confined to the shape-key path (hit rows
# improve 15-27%, scaling with token count; bypass/miss rows are flat).
# Sources: per-query keyed-init removal (BLAKE3 key schedule -> 4 adds),
# XXH64_update inlined into pg_hash_sink.c (header-only build) instead of
# cross-TU calls, and the 512B staging layer deleted (records now go
# straight into XXH64's internal 32-byte buffer). Code size: -1983 lines
# of vendored BLAKE3, +489 lines of header-only XXH64 (xxh64.h, verbatim
# extraction from xxHash v0.8.3, pinned by upstream sanity vectors).
