# supavisor

## Overview

Supavisor is a scalable, cloud-native Postgres connection pooler. It's capable of supporting millions of Postgres end-client connections into a stateful pool of native Postgres database connections.

For Postgres clients, the goal is to provide Postgres connection pools as a service so that clients don't have to worry about connection limits of their Postgres database.

For managers of Postgres databases, supavisor makes managing Postgres clusters easy by handling Postgres high-availability cluster configuration and state.

## Docs

- [Installation and usage](https://github.com/supabase/supavisor/wiki/Installation-and-Usage)
- [Metrics](https://github.com/supabase/supavisor/wiki/Metrics)

## Features

- Fast
  - Within 90% throughput as compared to `pgbouncer` running `pgbench` locally
- Scalable
  - 1 million Postgres connections on a cluster
  - 250_000 idle connections on a single 16 core node with 64GB of ram
- Multi-tenant
  - Connect to multiple different Postgres instances/clusters
- Single-tenant
  - Easy drop-in replacement for `pgbouncer`
- Pool mode support per tenant
  - Transaction
- Cloud-native
  - Cluster-able
  - Resiliant during cluster resizing
  - Supports rolling and blue/green deployment strategies
  - NOT run in a serverless environment
  - NOT dependant on Kubernetes
- Observable
  - Easily understand throughput by tenant, tenant database or individual connection
  - Prometheus `/metrics` endpoint
- Manageable
  - OpenAPI spec at `/api/openapi`
  - SwaggarUI at `/swaggerui`
- Highly available
  - When deployed as a Supavisor cluster and a node dies connection pools should be quickly spun up or already available on other nodes when clients reconnect
- Connection buffering
  - Brief connection buffering for transparent database restarts

## Future Work

- Load balancing
  - Queries can be load balanced across read-replicas
  - Load balancing is independant of Postgres high-availability management (see below)
- Query caching
  - Query results are optionally cached in the pool cluster and returned before hitting the tenant database
- Session pooling
  - Like `pgbouncer`
- Multi-protocol Postgres query interface
  - Postgres binary
  - HTTPS
  - Websocket
- Postgres high-availability management
  - Primary database election on primary failure
  - Health checks
  - Push button read-replica configuration
- Config as code
  - Not noly for the supavisor cluster but tenant databases and tenant database clusters as well
  - Pulumi / terraform support

## Inspiration

- [pgbouncer](https://www.pgbouncer.org/)
- [stolon](https://github.com/sorintlab/stolon)
- [pgcat](https://github.com/levkk/pgcat)
- [odyssey](https://github.com/yandex/odyssey)
- [crunchy-proxy](https://github.com/CrunchyData/crunchy-proxy)
- [pgpool](https://www.pgpool.net/mediawiki/index.php/Main_Page)
- [pgagroal](https://github.com/agroal/pgagroal)

## Commercial Inspiration

- [proxysql.com](https://proxysql.com/)
- [Amazon RDS Proxy](https://aws.amazon.com/rds/proxy/)
- [Google Cloud SQL Proxy](https://github.com/GoogleCloudPlatform/cloud-sql-proxy)

## Benchmarking

Benchmarking for stateful throughput:

Make sure we benchmark for typical server-side stateful database connection pools.

- Run pgbench for a minimum of 60 seconds
- Connection init will be less of a percentage of time

Benchmarking for serverless use-case:

Make sure we benchmark how long it takes to connect, run one transaction and disconnnect.
