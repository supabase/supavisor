Launch the Supavisor application:

```
make dev
```

Start the Supavisor database to store tenant information:

```
make db_start && make db_migrate
```

You need to add tenants to the database. For example, the following request will
add the `dev_tenant` with credentials to the database set up earlier.

```bash
curl  -X PUT \
  'http://localhost:4000/api/tenants/dev_tenant' \
  --header 'Accept: */*' \
  --header 'User-Agent: Thunder Client (https://www.thunderclient.com)' \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.M9jrxyvPLkUxWgOYSf5dNdJ8v_eRrq810ShFRT8N-6M' \
  --header 'Content-Type: application/json' \
  --data-raw '{
  "tenant": {
    "db_host": "localhost",
    "db_port": 6432,
    "db_database": "postgres",
    "ip_version": "auto",
    "enforce_ssl": false,
    "require_user": false,
    "auth_query": "SELECT rolname, rolpassword FROM pg_authid WHERE rolname=$1;",
    "users": [
      {
        "db_user": "postgres",
        "db_password": "postgres",
        "pool_size": 20,
        "mode_type": "transaction",
        "is_manager": true
      }
    ]
  }
}'
```

Now, it's possible to connect through the proxy. By default, Supavisor uses port
`6543` for transaction mode and `5432` for session mode:

```
psql postgresql://postgres.dev_tenant:postgres@localhost:6543/postgres
```

> :warning: The tenant's ID is incorporated into the username and separated by
> the `.` symbol. For instance, for the username `some_username` belonging to
> the tenant `some_tenant`, the modified username will be
> `some_username.some_tenant`. This approach enables the system to support
> multi-tenancy on a single IP address.

As a general note, if you are not using the `Makefile` you will have to set a
`VAULT_ENC_KEY` which should be at least 32 bytes long.

## General Commands

Here's an overview of the commands and the options you can use.

### Add/update tenant

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
    "ip_version": "auto", // "auto" | "v4" | "v6"
    "require_user": true, // true | false
    "upstream_ssl": true, // true | false,
    "enforce_ssl": false, // true | false,
    "upstream_verify": "peer", // "none" | "peer"
    "upstream_tls_ca": "-----BEGIN CERTIFICATE-----\nblalblalblablalblalblaba\n-----END CERTIFICATE-----\n", // "",
    "default_max_clients": 200,
    "default_pool_size": 15,
    "users": [
      {
        "db_user": "postgres",
        "db_password": "postgres",
        "mode_type": "transaction",
        "pool_checkout_timeout": 100,
        "pool_size": 10
      }
    ]
  }
}'
```

## Delete tenant

To delete a tenant, send the following request:

```bash
curl -X DELETE \
  'http://localhost:4000/api/tenants/dev_tenant' \
  --header 'Accept: application/json' \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNjQ1MTkyODI0LCJleHAiOjE5NjA3Njg4MjR9.M9jrxyvPLkUxWgOYSf5dNdJ8v_eRrq810ShFRT8N-6M'
```

API documentation can be found at [http://localhost:4000/swaggerui](http://localhost:4000/swaggerui)
