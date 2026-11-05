Supavisor can carry Postgres connections over WebSocket, as used by the `Pool` and `Client` of [Neon's serverless driver](https://github.com/neondatabase/serverless). This is useful where TCP connections can't be opened, like edge functions, but a session or an interactive transaction is still needed.

## Usage

Point the driver at Supavisor's `/v2` endpoint, and use the same connection string as for Postgres:

```js
import { Pool, neonConfig } from '@neondatabase/serverless'

neonConfig.wsProxy = () => 'supavisor.example.com/v2/'

const pool = new Pool({
  connectionString: 'postgresql://postgres.dev_tenant:postgres@localhost:6543/postgres'
})

const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id])
```

Without TLS, set `neonConfig.useSecureWebSocket` to `false`.

## Notes

- Tenants can't be selected by SNI.
