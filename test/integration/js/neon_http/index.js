// Ported from tests/cli/http.test.ts and tests/cli/httpTransaction.test.ts in
// https://github.com/neondatabase/serverless
// Copyright (c) 2022 - 2025 Neon Inc. MIT License.

import { t } from '../shared/test.js' // eslint-disable-line
import util from 'node:util'
import { WebSocket } from 'ws'
import { neon, neonConfig, Pool, SqlTemplate } from '@neondatabase/serverless'
import { sampleQueries } from './sampleQueries.js'

globalThis.WebSocket = WebSocket

neonConfig.fetchEndpoint = () => process.env.HTTP_SQL_ENDPOINT
neonConfig.wsProxy = () => process.env.HTTP_SQL_WS_PROXY
neonConfig.useSecureWebSocket = false

const DATABASE_URL = `postgres://${encodeURIComponent(process.env.PGUSER)}:${encodeURIComponent(process.env.PGPASS)}@${process.env.PGHOST}:${process.env.PGPORT}/${process.env.PGDATABASE}`

const sql = neon(DATABASE_URL)
const sqlFull = neon(DATABASE_URL, { fullResults: true })
const pool = new Pool({ connectionString: DATABASE_URL })

const inspect = (x) => util.inspect(x, { depth: null, sorted: true })
const errorMessage = (promise) => promise.then(() => 'no error', (e) => e.message)
const contains = (text, part) => (text.includes(part) ? part : text)

// http.test.ts

t('http query results match WebSocket query results', { timeout: 60 }, async () => {
  const client = await pool.connect()
  const mismatches = []

  for (const queryPromise of sampleQueries(sqlFull)) {
    const { query, params } =
      queryPromise.queryData instanceof SqlTemplate
        ? queryPromise.queryData.toParameterizedQuery()
        : queryPromise.queryData

    const [httpResult, wsResult] = await Promise.all([queryPromise, client.query(query, params)])

    // account for known/accepted differences:
    // * http results are plain Objects, not Result instances
    // * http results lack `oid` and `RowCtor` fields (which are both usually `null`)
    // * http result `fields` array contains plain Objects, not Field instances
    // * http results have `"viaNeonFetch": true`
    const httpResultProcessed = { ...httpResult, oid: null, RowCtor: null }
    const wsResultProcessed = {
      ...wsResult,
      fields: wsResult.fields.map((f) => ({ ...f })),
      viaNeonFetch: true
    }

    if (inspect(httpResultProcessed) !== inspect(wsResultProcessed))
      mismatches.push({ query, http: httpResultProcessed, ws: wsResultProcessed })
  }

  client.release()
  return [inspect([]), inspect(mismatches)]
})

t('sql.query() http results for uncast binary data (it might be preferable if this test would fail)', async () => {
  const abc = await sql.query('SELECT $1 AS bytea', [new Uint8Array([65, 66, 67])])
  // over TCP or WebSockets or using sql`...`, this would be { "bytea": "ABC" }
  return [inspect([{ bytea: '\\x414243' }]), inspect(abc)]
})

t('composable SQL and unsafe raw SQL', async () => {
  const q = sql`
    SELECT
      ${sql.query('0 AS n')},
      ${123} AS z, ${sql.unsafe('"generate_series"')}
      ${sql`FROM generate_series(${1}::int, ${sql`4`})`}
    UNION SELECT
      ${sql.query('1 AS n', [])},
      ${789} AS z, ${sql.unsafe('x')}
      ${sql`FROM generate_series(${sql`${1}::int`}, ${3}::int) AS x`}
    ${sql`ORDER BY generate_series, z LIMIT ${3}`}
  `

  const result = await q
  return [
    inspect([
      { generate_series: 1, z: '123', n: 0 },
      { generate_series: 1, z: '789', n: 1 },
      { generate_series: 2, z: '123', n: 0 }
    ]),
    inspect(result)
  ]
})

t('options to `neon()` and options on queries', async () => {
  const sqlff = neon(DATABASE_URL, { arrayMode: false, fullResults: false })
  const sqlft = neon(DATABASE_URL, { arrayMode: false, fullResults: true })
  const sqltf = neon(DATABASE_URL, { arrayMode: true, fullResults: false })
  const sqltt = neon(DATABASE_URL, { arrayMode: true, fullResults: true })

  const ff = await sqlff`SELECT 'xyz' AS str` // arrayMode false, fullResults false
  const ft = await sqlft`SELECT 'xyz' AS str` // arrayMode false, fullResults true
  const tf = await sqltf`SELECT 'xyz' AS str` // arrayMode true, fullResults false
  const tt = await sqltt`SELECT 'xyz' AS str` // arrayMode true, fullResults true

  // check per-query option overrides
  const fftt = await sqlff.query("SELECT 'xyz' AS str", [], { arrayMode: true, fullResults: true })
  const ttff = await sqltt.query("SELECT 'xyz' AS str", [], { arrayMode: false, fullResults: false })

  const summary = (r) => [r.fields[0].name, r.fields[0].dataTypeID, r.command, r.rowCount, r.rowAsArray]

  return [
    inspect({
      ff: 'xyz',
      ft: ['xyz', ['str', 25, 'SELECT', 1, false]],
      tf: 'xyz',
      tt: ['xyz', ['str', 25, 'SELECT', 1, true]],
      fftt: ['xyz', ['str', 25, 'SELECT', 1, true]],
      ttff: 'xyz'
    }),
    inspect({
      ff: ff[0].str,
      ft: [ft.rows[0].str, summary(ft)],
      tf: tf[0][0],
      tt: [tt.rows[0][0], summary(tt)],
      fftt: [fftt.rows[0][0], summary(fftt)],
      ttff: ttff[0].str
    })
  ]
})

t('errors match WebSocket query errors', async () => {
  const q = 'SELECT 123 WHERE x'

  const [httpErr, wsErr] = await Promise.all([
    sql.query(q).catch((e) => e),
    pool.query(q).catch((e) => e)
  ])

  // account for known/accepted differences
  httpErr.length = wsErr.length // http errors don't have a `length` property
  httpErr.name = wsErr.name // http errors are named 'NeonDbError' rather than plain 'error'
  wsErr.sourceError = undefined // this property is unique to http errors

  return [
    inspect(['column "x" does not exist', { ...wsErr }]),
    inspect([httpErr.message, { ...httpErr }])
  ]
})

t('http queries with too few or too many parameters', async () => {
  return [
    inspect(['bind message supplies 0 parameters', 'bind message supplies 2 parameters']),
    inspect([
      contains(await errorMessage(sql.query('SELECT $1', [])), 'bind message supplies 0 parameters'),
      contains(await errorMessage(sql.query('SELECT $1', [1, 2])), 'bind message supplies 2 parameters')
    ])
  ]
})

t('timeout aborting an http query', async () => {
  const signal = AbortSignal.timeout(250)
  const message = await errorMessage(sql.query('SELECT pg_sleep(2)', [], { fetchOptions: { signal } }))
  return ['aborted', contains(message, 'aborted')]
})

t('timeout not aborting an http query', async () => {
  const signal = AbortSignal.timeout(2500)
  const result = await sql.query('SELECT pg_sleep(.25)', [], { fetchOptions: { signal } })
  return [inspect([{ pg_sleep: '' }]), inspect(result)]
})

t('database URL with wrong user to `neon()`', async () => {
  const badUrl = DATABASE_URL.replace('//', '//x')
  const httpMessage = await errorMessage(neon(badUrl)`SELECT ${1}::int AS one`)
  const wsMessage = await errorMessage(new Pool({ connectionString: badUrl }).query('SELECT 1'))
  return [wsMessage, httpMessage]
})

t('database URL with wrong password to `neon()`', async () => {
  const sqlBad = neon(DATABASE_URL.replace('@', 'x@'))
  const message = await errorMessage(sqlBad`SELECT ${1}::int AS one`)
  return ['password authentication failed', contains(message, 'password authentication failed')]
})

// httpTransaction.test.ts

t('basic batch query with array of sql', async () => {
  const [[a], [b]] = await sql.transaction([
    sql`SELECT ${1}::int AS "batchInt"`,
    sql`SELECT ${'hello'} AS "batchStr"`
  ])
  return [inspect([1, 'hello']), inspect([a.batchInt, b.batchStr])]
})

t('basic batch query with function', async () => {
  const [[a], [b]] = await sql.transaction((txn) => [
    txn`SELECT ${2}::int AS "batchInt"`,
    txn`SELECT ${'goodbye'} AS "batchStr"`
  ])
  return [inspect([2, 'goodbye']), inspect([a.batchInt, b.batchStr])]
})

t('empty batch query with function', async () => {
  const emptyResult = await sql.transaction(() => [])
  return [0, emptyResult.length]
})

t('batch query with array using mix of template strings and query function', async () => {
  const [[a], [b]] = await sql.transaction([
    sql`SELECT ${1}::int AS "batchInt"`,
    sql.query('SELECT $1 AS "batchStr"', ['hello'])
  ])
  return [inspect([1, 'hello']), inspect([a.batchInt, b.batchStr])]
})

t('batch query with function using mix of template strings and query function', async () => {
  const [[a], [b]] = await sql.transaction((txn) => [
    txn`SELECT ${2}::int AS "batchInt"`,
    txn.query('SELECT $1 AS "batchStr"', ['goodbye'])
  ])
  return [inspect([2, 'goodbye']), inspect([a.batchInt, b.batchStr])]
})

t('empty batch query with array', async () => {
  const emptyResult = await sql.transaction([])
  return [0, emptyResult.length]
})

t('option setting on `transaction()`', async () => {
  const [a, b] = await sql.transaction(
    (txn) => [txn`SELECT ${1}::int AS "batchInt"`, txn`SELECT ${'hello'} AS "batchStr"`],
    { arrayMode: true, isolationLevel: 'Serializable', readOnly: true } // arrayMode changes result format below
  )
  return [inspect([1, 'hello']), inspect([a[0][0], b[0][0]])]
})

t('option setting on `neon()`', async () => {
  const sqlArr = neon(DATABASE_URL, {
    arrayMode: true, // arrayMode changes result format below
    isolationLevel: 'RepeatableRead'
  })
  const [a, b] = await sqlArr.transaction((txn) => [
    txn`SELECT ${1}::int AS "batchInt"`,
    txn`SELECT ${'hello'} AS "batchStr"`
  ])
  return [inspect([1, 'hello']), inspect([a[0][0], b[0][0]])]
})

t('option setting on `transaction()` overrides option setting on `neon()` (a)', async () => {
  const sqlArr = neon(DATABASE_URL, { arrayMode: true })
  const [a, b] = await sqlArr.transaction(
    (txn) => [txn`SELECT ${1}::int AS "batchInt"`, txn`SELECT ${'hello'} AS "batchStr"`],
    { arrayMode: false }
  )
  return [inspect([1, 'hello']), inspect([a[0].batchInt, b[0].batchStr])]
})

t('option setting on `transaction()` overrides option setting on `neon()` (b)', async () => {
  const [a, b] = await sql.transaction(
    (txn) => [txn`SELECT ${1}::int AS "batchInt"`, txn`SELECT ${'hello'} AS "batchStr"`],
    { fullResults: true }
  )
  return [inspect([1, 'hello']), inspect([a.rows[0].batchInt, b.rows[0].batchStr])]
})

t('option setting on individual queries within a batch (unsupported by types)', async () => {
  const [[a], [b]] = await sql.transaction((txn) => [
    txn`SELECT ${1}::int AS "batchInt"`,
    txn.query('SELECT $1 AS "batchStr"', ['hello'], { arrayMode: true })
  ])
  return [inspect([1, 'hello']), inspect([a.batchInt, b[0]])]
})
