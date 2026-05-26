# HTTP `/sql`

Supavisor exposes an HTTP endpoint that accepts SQL queries as JSON. It
speaks the [`@neondatabase/serverless`](https://github.com/neondatabase/serverless)
wire format, so clients that target Neon work against Supavisor with a
single config line.

## How it works

The HTTP request is handled by a request-scoped client that joins the
same tenant pool used by TCP clients:

1. `SupavisorWeb.Plugs.NeonAuth` parses the `Neon-Connection-String`
   header, looks up the tenant + user, runs the CircuitBreaker and
   allow_list gates, and verifies the password against the cached
   SCRAM-SHA-256 secrets.
2. `Supavisor.HttpSql.ClientHandler.run_query/4` calls the standard
   `Supavisor.start_dist` + `Supavisor.subscribe` + `:poolboy.checkout` +
   `Supavisor.DbHandler.checkout` chain, exactly as a TCP client would.
   The HTTP process registers as a subscriber of the tenant `Manager`,
   so it counts against the tenant's `max_clients` cap.
3. The DbHandler worker writes backend wire bytes back to the HTTP
   process as Erlang `{:db_bytes, _}` messages (a new `{:proc, pid}`
   socket variant in `Supavisor.HandlerHelpers.sock_send/2`). No
   Postgrex pool, no loopback TCP hop.
4. A single extended-query round-trip
   (`Parse + Bind + Describe + Execute + Sync`) drives the query, with
   every parameter sent in text format — no per-OID coercion needed.
5. `Supavisor.HttpSql.WireDecoder` parses the response stream into
   `{columns, rows, command, num_rows}`, and `ResponseBuilder` turns
   that into the Neon JSON body.

## Enable

Off by default. Two switches:

1. `HTTP_SQL_ENABLED=true` — global kill switch, set in the environment.
2. `feature_flags.http_sql=true` — set per-tenant via the admin API:

   ```bash
   curl -X PATCH https://<host>/api/tenants/<external_id> \
     -H "Authorization: Bearer $API_JWT_SECRET" \
     -H 'Content-Type: application/json' \
     -d '{"tenant": {"feature_flags": {"http_sql": true}}}'
   ```

## Single query

```bash
curl -X POST https://<host>/sql \
  -H 'Content-Type: application/json' \
  -H 'Neon-Connection-String: postgres://postgres.dev_tenant:secret@<host>/postgres' \
  -d '{"query": "SELECT $1::int + 1 AS n", "params": [41]}'
```

Response:

```json
{
  "command": "SELECT",
  "rowCount": 1,
  "fields": [{"name": "n", "dataTypeID": 23, "format": "text", ...}],
  "rows": [{"n": "42"}]
}
```

Cell values are always Postgres text representation as JSON strings;
`null` stays `null`. Clients decode locally via `pg-types` using the
`dataTypeID` (OID).

Headers the driver may send (all optional):

- `Neon-Array-Mode: true` — rows as positional arrays instead of column-keyed objects.
- `Neon-Raw-Text-Output: true` — always honored (the only mode supported).

## Batch / transaction

```json
{
  "queries": [
    {"query": "INSERT INTO t(x) VALUES ($1)", "params": [1]},
    {"query": "SELECT count(*) FROM t",      "params": []}
  ]
}
```

Runs in a single server-side transaction. Response wraps per-query
results under `"results"`. Roll back on the first error.

Transaction mode is configurable via headers:

- `Neon-Batch-Isolation-Level: ReadCommitted | RepeatableRead | Serializable | ReadUncommitted`
- `Neon-Batch-Read-Only: true | false`
- `Neon-Batch-Deferrable: true | false`

## Drop-in for `@neondatabase/serverless`

```js
import { neon, neonConfig } from '@neondatabase/serverless'

neonConfig.fetchEndpoint = (host) => `https://${host}/sql`

const sql = neon('postgres://postgres.dev_tenant:secret@<host>/postgres')
const rows = await sql`SELECT id, email FROM users WHERE id = ${userId}`
```

`@vercel/postgres` and `drizzle-orm/neon-http` work the same way.

## Authentication

Password from the `Neon-Connection-String` header is checked
synchronously against the tenant user's SCRAM-SHA-256 secrets before any
backend connection is made. Repeated wrong passwords trip the tenant
circuit breaker (10 failures over 150 s → 120 s block, keyed by client
IP). `Authorization: Bearer <jwt>` is not supported in this release —
requests carrying it get 401.

## Saturation

HTTP requests share the tenant's pool with TCP clients. Each in-flight
request occupies a `Supavisor.Manager` subscription slot for the
duration of the query; when the tenant hits its configured
`max_clients`, further HTTP requests are rejected with HTTP **429** and
a `max_clients_rejected` Prometheus counter ticks. The pool itself is
configured per-tenant (via the admin API on the tenant/user records),
not via global HTTP env vars — see the
[Configuration](../configuration/env.md) reference for tenant pool
sizing.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `HTTP_SQL_ENABLED` | `false` | Global kill switch. |
| `HTTP_SQL_MAX_QUERY_BYTES` | `1048576` | Request body cap. Over → 413. |
| `HTTP_SQL_MAX_RESPONSE_ROWS` | `10000` | Row cap per query. Over → 413 `row_limit_exceeded`. |
| `HTTP_SQL_MAX_RESPONSE_BYTES` | `16777216` | Serialized response cap. Over → 413 `response_too_large`. |
| `HTTP_SQL_REQUEST_TIMEOUT_MS` | `30000` | Query timeout (DbHandler.checkout + backend round-trip); also body-read timeout. |
| `HTTP_SQL_TRUSTED_PROXIES` | empty | Comma-separated CIDR list. `X-Forwarded-For` honored only when the immediate peer is inside this list; otherwise `conn.remote_ip` is used. |

The previously documented `HTTP_SQL_POOL_*` variables are gone: HTTP
requests now use the tenant's existing pool instead of a dedicated
Postgrex pool. Tune `default_pool_size` / `max_clients` on the tenant
or user record to size the pool.

## Errors

Error responses match the `pg`-style fields the Neon driver expects:
`code`, `severity`, `message`, `detail`, `hint`, `position`, `where`,
`schema`, `table`, `column`, `constraint`, `file`, `line`, `routine`.
The `code` is the Postgres SQLSTATE (e.g. `"23505"`) for backend
errors, or a stable string (`"unauthorized"`, `"circuit_open"`,
`"row_limit_exceeded"`, `"response_too_large"`, `"feature_disabled"`,
`"malformed_request"`) for gates that fire before the query runs.

HTTP 429 is returned when the tenant's `max_clients` limit is hit.
