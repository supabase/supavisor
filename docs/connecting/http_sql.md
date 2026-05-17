# HTTP `/sql`

Supavisor exposes an HTTP endpoint that accepts SQL queries as JSON. It
speaks the [`@neondatabase/serverless`](https://github.com/neondatabase/serverless)
wire format, so clients that target Neon work against Supavisor with a
single config line.

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

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `HTTP_SQL_ENABLED` | `false` | Global kill switch. |
| `HTTP_SQL_POOL_SIZE` | `5` | Postgrex pool size per `(tenant, user, password)`. |
| `HTTP_SQL_POOL_MAX_TOTAL` | `1000` | Cap on total live pools; LRU eviction past this. |
| `HTTP_SQL_POOL_IDLE_TTL_SECONDS` | `60` | Idle pool sweep threshold. |
| `HTTP_SQL_MAX_QUERY_BYTES` | `1048576` | Request body cap. Over → 413. |
| `HTTP_SQL_MAX_RESPONSE_ROWS` | `10000` | Row cap per query. Over → 413 `row_limit_exceeded`. |
| `HTTP_SQL_MAX_RESPONSE_BYTES` | `16777216` | Serialized response cap. Over → 413 `response_too_large`. |
| `HTTP_SQL_REQUEST_TIMEOUT_MS` | `30000` | Postgrex query timeout; also body-read timeout. |
| `HTTP_SQL_TRUSTED_PROXIES` | empty | Comma-separated CIDR list. `X-Forwarded-For` honored only when the immediate peer is inside this list; otherwise `conn.remote_ip` is used. |

## Errors

Error responses match the `pg`-style fields the Neon driver expects:
`code`, `severity`, `message`, `detail`, `hint`, `position`, `where`,
`schema`, `table`, `column`, `constraint`, `file`, `line`, `routine`.
The `code` is the Postgres SQLSTATE (e.g. `"23505"`) for backend
errors, or a stable string (`"unauthorized"`, `"circuit_open"`,
`"row_limit_exceeded"`, `"response_too_large"`, `"feature_disabled"`,
`"malformed_request"`) for gates that fire before the query runs.
