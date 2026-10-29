Supavisor can run queries sent over HTTP, using the protocol of the HTTP mode of [Neon's serverless driver](https://github.com/neondatabase/serverless). This is useful where Postgres connections can't be kept open, like serverless and edge functions.

## Usage

Point the driver at Supavisor's `/sql` endpoint, and use the same connection string as for Postgres:

```js
import { neon, neonConfig } from '@neondatabase/serverless'

neonConfig.fetchEndpoint = 'https://supavisor.example.com/sql'

const sql = neon('postgresql://postgres.dev_tenant:postgres@localhost:6543/postgres')

const rows = await sql`SELECT * FROM users WHERE id = ${id}`

const [users, posts] = await sql.transaction([
  sql`SELECT * FROM users`,
  sql`SELECT * FROM posts`
])
```

## Notes

- Tenants can't be selected by SNI.
- Responses are capped at `HTTP_SQL_MAX_RESPONSE_BYTES` (10 MiB by default), above which the request fails with status 507.
