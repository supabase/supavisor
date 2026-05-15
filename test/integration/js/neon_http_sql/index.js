/**
 * Manual smoke test: runs `@neondatabase/serverless` against a live
 * Supavisor /sql endpoint.
 *
 * Prereqs (one-time, against a `make dev` instance):
 *
 *   HTTP_SQL_ENABLED=true make dev
 *
 *   curl -X PATCH http://localhost:4000/api/tenants/dev_tenant \
 *     -H "Authorization: Bearer dev" \
 *     -H 'Content-Type: application/json' \
 *     -d '{"tenant": {"feature_flags": {"http_sql": true}}}'
 *
 * Run:
 *
 *   cd test/integration/js && npm install   # once
 *
 *   HTTP_SQL_ENDPOINT=http://localhost:4000/sql \
 *   PGUSER=postgres.dev_tenant PGPASS=postgres \
 *   PGHOST=localhost PGPORT=4000 PGDATABASE=postgres \
 *     node neon_http_sql/index.js
 *
 * Exits 0 on success, 1 on first failure.
 */

import { t } from '../shared/test.js'
import { neon, neonConfig } from '@neondatabase/serverless'

// Force the HTTP helper to hit our Supavisor endpoint instead of api.neon.tech.
neonConfig.fetchEndpoint = (host, _port, _opts) =>
  process.env.HTTP_SQL_ENDPOINT || `http://${host}:4000/sql`

// Body of the connection string is required to construct the driver, but the
// host/port are overridden by `fetchEndpoint` above.
const connectionString =
  `postgres://${encodeURIComponent(process.env.PGUSER)}:${encodeURIComponent(process.env.PGPASS)}` +
  `@${process.env.PGHOST}:${process.env.PGPORT}/${process.env.PGDATABASE}`

const sql = neon(connectionString)

t('SELECT scalar', async () => {
  const rows = await sql`SELECT 1 AS one`
  return [1, Number(rows[0].one)]
})

t('SELECT with parameter', async () => {
  const rows = await sql`SELECT ${41}::int + 1 AS n`
  return [42, Number(rows[0].n)]
})

t('NULL round-trips', async () => {
  const rows = await sql`SELECT NULL::int AS n`
  return [null, rows[0].n]
})

t('SELECT with text', async () => {
  const rows = await sql`SELECT 'hi' AS s`
  return ['hi', rows[0].s]
})

t('Boolean', async () => {
  const rows = await sql`SELECT true AS b`
  return [true, rows[0].b]
})

t('Date', async () => {
  const rows = await sql`SELECT '2026-05-15'::date AS d`
  return ['2026-05-15', rows[0].d.toString()]
})

t('Aggregate count', async () => {
  const rows = await sql`SELECT count(*)::int AS c FROM generate_series(1,3)`
  return [3, Number(rows[0].c)]
})
