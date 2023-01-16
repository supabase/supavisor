# pg_edge

## Overview

pg_edge (name tbd) is a scalable cloud-native Postgres connection pooler capable of supporting millions of Postgres end-client connections into a stateful pool of native Postgres database connections.

For Postgres clients, goal is to provide Postgres connection pools as a service such that clients don't have to worry about connection limits of their Postgres database.

For managers of Postgres databases, pg_edge should make managing Postgres clusters easy by handling Postgres high-availability cluster configuration and state.

## Postgres Features

**Features not listed in priority**

- Fast
  - Within 90% throughput as compared to `pgbouncer` running `pgbench` locally
- Scalable
  - 1 million Postgres connections on a cluster
  - 250_000 idle connections on a single 16 core node with 64GB of ram
- Multi-tenant
  - Connect to multiple different Postgres instances/clusters
- Load balancing
  - Queries can be load balanced across read-replicas
  - Load balancing is independant of Postgres high-availability management (see below)
- Query caching
  - Query results are optionally cached in the pool cluster and returned before hitting the tenant database
- Transaction pooling
  - Like pgbouncer
- Session pooling
  - Like pgbouncer
- Multi-protocol Postgres query interface
  - Postgres binary
  - HTTPS
  - Websocket
- Connection buffering
  - Supports a fast (minutes) tenant Postgres database restart without interupting clients (aside from query latency)
- High-availability
  - When deployed as a pg_edge cluster and a pg_edge node dies connection pools should be quickly spun up or already available on other nodes when clients reconnect
- Postgres high-availability management
  - Primary database election on primary failure
  - Health checks
  - Push button read-replica configuration
  - What else?
- Deployable as a single or multi-tenant proxy
  - Direct replacement for `pgbouncer`
  - Uses specific `pg_edge` schema in metadata database so when used as a `pgbouncer` replacement it can use the local database as the metadata database

## General Features

- Cloud-native
  - Cluster-able
  - Cluster should handle dynamic resizing
  - Support rolling and blue/green deployment strategies
  - Self-heal if instances come and go
  - NOT run in a serverless environment
  - NOT dependant on Kubernetes
- Observability
  - Easily understand throughput by tenant, tenant database or individual connection
  - Prometheus `/metrics` endpoint
  - Admin UI to add tenants, view metrics, sort tenants by throughput, ban tenants, etc
- Config as code
  - Not noly for the pg_edge cluster but tenant databases and tenant database clusters as well
  - Pulumi / terraform support

## Inspiration

- [pgbouncer](https://www.pgbouncer.org/)
- [stolon](https://github.com/sorintlab/stolon)
- [pgcat](https://github.com/levkk/pgcat)
- [odyssey](https://github.com/yandex/odyssey)
- [crunchy-proxy](https://github.com/CrunchyData/crunchy-proxy)
- [pgpool](https://www.pgpool.net/mediawiki/index.php/Main_Page)
- [pgagroal](https://github.com/agroal/pgagroal)

## Installation

tbd
