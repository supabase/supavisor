## pgbench

Benchmark against Supavisor on Supabase.

```bash
pgbench 'postgres://postgres.jqmckcjykfylxxvsdcdt@aws-0-eu-central-1.pooler.supabase.com:6543/postgres' -Srn -T 60 -j 8 -c 150 -P 10 -M extended
```

Benchmark against PgBouncer on Supabase.

```bash
pgbench 'postgres://postgres@db.jqmckcjykfylxxvsdcdt.supabase.co:6543/postgres' -Srn -T 60 -j 8 -c 8 -P 10 -M extended
```
