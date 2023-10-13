Launch the Supavisor application:

```
make dev
```

You need to add tenants to the database. For example, the following request will add the `dev_tenant` with credentials to the database set up earlier.

## Add/update tenant

```bash
curl -X PUT \
  'http://localhost:4000/api/tenants/dev_tenant' \
  --header 'Accept: application/json' \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.M9jrxyvPLkUxWgOYSf5dNdJ8v_eRrq810ShFRT8N-6M' \
  --header 'Content-Type: application/json' \
  --data-raw '{
  "tenant": {
    "db_host": "localhost",
    "db_port": 6432,
    "db_database": "postgres",
    "ip_version": "auto", // "auto" | v4 | v6
    "require_user": true, // true | false
    "upstream_ssl": true, // true | false,
    "enforce_ssl": false, // true | false,
    "upstream_verify": "peer", // "none" | "peer"
    "upstream_tls_ca": "-----BEGIN CERTIFICATE-----\nblalblalblablalblalblaba\n-----END CERTIFICATE-----\n", // ""
    "users": [
      {
        "db_user": "postgres",
        "db_password": "postgres",
        "pool_size": 20,
        "mode_type": "transaction",
        "pool_checkout_timeout": 100
      }
    ]
  }
}'
```

Now, it's possible to connect through the proxy. By default, Supavisor uses port `6543` for transaction mode and `5432` for session mode:

```
psql postgresql://postgres.dev_tenant:postgres@localhost:6543/postgres
```

> :warning: The tenant's ID is incorporated into the username and separated by the `.` symbol. For instance, for the username `some_username` belonging to the tenant `some_tenant`, the modified username will be `some_username.some_tenant`. This approach enables the system to support multi-tenancy on a single IP address.

## Delete tenant

To delete a tenant, send the following request:

```bash
curl -X DELETE \
  'http://localhost:4000/api/tenants/dev_tenant' \
  --header 'Accept: application/json' \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.M9jrxyvPLkUxWgOYSf5dNdJ8v_eRrq810ShFRT8N-6M'
```

API documentation can be found at [http://localhost:4000/swaggerui](http://localhost:4000/swaggerui)

## Deploying your app with Fly.io

The `toml.yaml` file should be in the `deploy/fly` directory of Supavisor.

Type the following command in your terminal:

```bash
fly launch
```

Choose a name for your app when prompted, then answer "yes" to the following question:

```bash
Would you like to copy its configuration to the new app? (y/N)
```

Next, select an organization and choose a region. You don't need to deploy the app yet.

Since the pooler uses an additional port (7654) for the PostgreSQL protocol, you need to reserve an IP address:

```bash
fly ips allocate-v4
```

Set your app's secrets by running the following command:

```bash
fly secrets set DATABASE_URL="ecto://postgres:postgres@localhost:6432/postgres" \
VAULT_ENC_KEY="some_vault_secret" \
API_JWT_SECRET="some_api_secret" \
METRICS_JWT_SECRET="some_metrics_secret" \
SECRET_KEY_BASE="some_kb_secret"
```

Replace the example values with your actual secrets.

Finally, deploy your app using the following command:

```bash
fly deploy
```

This will deploy your app on Fly.io
