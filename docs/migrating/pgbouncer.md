Migrating from PgBouncer is straight forward once a Supavisor cluster is setup
and a database has been added as a `tenant`.

No application level code changes should be required other than a connection
string change. Both `transaction` and `session` pool mode behavior for Supavisor
is the same as PgBouncer, except for the session settings described in
[Session settings in transaction mode](#session-settings-in-transaction-mode).

One caveat during migration is running two connection poolers at the same time.

When rolling out a connection string change to your application you will
momentarily need to support two connection pools to Postgres.

## Session settings in transaction mode

PgBouncer
[tracks](https://www.pgbouncer.org/config.html#track_extra_parameters)
`DateStyle`, `TimeZone` and `IntervalStyle` per client in transaction mode, and
sets them back when a server connection moves to another client. Supavisor does not. A session-level `SET` of one of these parameters,
or of `client_encoding` or `standard_conforming_strings`, stays on the server
connection, and every later client that gets that connection runs under it.

The other clients are not told. The `ParameterStatus` they received at startup
still shows the original values, so a driver that reads dates, timestamps or
intervals by those values can misread the results. A framework can cause this
without any hand-written `SET`: Rails, for example, sets `IntervalStyle` on
every connection it opens.

To change these parameters in transaction mode:

- Set them for one transaction with `SET LOCAL` (or `set_config` with
  `is_local` set to `true`).
- Set a default on the Postgres side for the database, or for the role that
  Supavisor's server connections log in as, for example
  `ALTER ROLE app_user SET TimeZone = 'UTC';`.
- Connect clients that need their own session settings in session mode.

Set the tenant's `txn_mode_leak_action` to `log` or `error` to find clients
that send a session-level `SET` in transaction mode. Queries the check skips,
such as those larger than 1 KB, are not caught.

## Check Postgres connection limit

Lets see what our connection limit is set to on our Postgres database:

```sql
show max_connections;
```

## Check used connections

Lets see how many connections we're currently using:

```sql
select count(*) from pg_stat_activity;
```

## Change Postgres `max_connections`

Based on the responses above configure the `default_pool_size` accordingly or
increase your `max_connections` limit on Postgres to accommodate two connection
poolers.

e.g if you're using 30 connections out of 100 and you set your
`default_pool_size` to 20 you have enough connections to run a new Supavisor
pool along side your PgBouncer pool.

If you are using 90 connections out of 100 and your `default_pool_size` is set
to 20 you will have problems during the deployment of your Supavisor connection
string because you will hit your Postgres `max_connections` limit.

## Verify Supavisor connections

Once we've got Supavisor started we can verify it's using the amount of
connections we set for `default_pool_size`:

```sql
SELECT
  COUNT(*) as count,
  usename,
  application_name
FROM pg_stat_activity
WHERE application_name ILIKE '%Supavisor%'
GROUP BY
  usename,
  application_name
ORDER BY application_name DESC;
```

## Celebrate!

You deserve it 🤙
