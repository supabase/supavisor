import { t } from '../shared/test.js' // eslint-disable-line
import { neon, neonConfig, NeonDbError } from '@neondatabase/serverless'

// The driver sends its queries to Neon unless told otherwise.
neonConfig.fetchEndpoint = () => process.env.HTTP_SQL_ENDPOINT

const connectionString = `postgres://${encodeURIComponent(process.env.PGUSER)}:${encodeURIComponent(process.env.PGPASS)}@${process.env.PGHOST}:${process.env.PGPORT}/${process.env.PGDATABASE}`

const sql = neon(connectionString)

t('Simple query', async () => {
  const rows = await sql`SELECT 1 AS one`
  return [1, rows[0].one]
})

t('Query with params', async () => {
  const rows = await sql`SELECT ${41}::int + 1 AS n, ${null}::text AS empty`
  return ['42,null', `${rows[0].n},${rows[0].empty}`]
})

t('Values are parsed by type', async () => {
  const [row] = await sql`SELECT true AS b, '2026-05-15T00:00:00Z'::timestamptz AS ts, '{"a":1}'::jsonb AS j, ${Buffer.from([1, 2])}::bytea AS bytes`
  return ['true,2026-05-15T00:00:00.000Z,1,1-2', `${row.b},${row.ts.toISOString()},${row.j.a},${[...row.bytes].join('-')}`]
})

t('Errors carry their code', async () => {
  const error = await sql`SELECT * FROM does_not_exist`.catch(e => e)
  return ['NeonDbError 42P01', `${error instanceof NeonDbError ? 'NeonDbError' : error} ${error.code}`]
})

t('Transactions', async () => {
  const [, [row]] = await sql.transaction([
    sql`CREATE TEMP TABLE t (n int)`,
    sql`SELECT current_setting('transaction_isolation') AS isolation`
  ], { isolationLevel: 'Serializable' })
  return ['serializable', row.isolation]
})

t('Full results', async () => {
  const result = await sql.query('SELECT 1 AS one', [], { fullResults: true })
  return ['SELECT 1 one', `${result.command} ${result.rowCount} ${result.fields[0].name}`]
})
