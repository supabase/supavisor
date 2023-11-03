All configuration options for a tenant are stored on the `tenant` record in the metadata database used by Supavisor.

A `tenant` is looked via the `external_id` discovered in the incoming client connection.

All `tenant` fields and their types are defined in the `Supavisor.Tenants.Tenant` module.

## Field Descriptions

`db_host` - the hostname of the server to connect to

`db_port` - the port of the server to connect to

`db_database` - the database of the Postgres instance

`external_id` - an id used in an external system used to lookup a tenant

`default_parameter_status` -

`ip_version` - the ip address type of the connection to the database server

`upstream_ssl` -

`upstream_verify` -

`upstream_tls_ca` -

`enforce_ssl` - enforce an SSL connection on client connections

`require_user` - require at least one `user` is created for a tenant

`auth_query` - the query to use when matching credential agains a client connection

`default_pool_size` - the default size of the database pool

`sni_hostname` - the hostname expected on an SSL client connection

`default_max_clients` - the default limit of client connections

`client_idle_timeout` - the maximum duration of an idle client connection

`default_pool_strategy` - the default strategy when pulling available connections from the pool queue
