help:
	@make -qpRr | egrep -e '^[a-z].*:$$' | sed -e 's~:~~g' | sort

.PHONY: dev
dev:
	MIX_ENV=dev \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	REGION=eu \
	FLY_ALLOC_ID=111e4567-e89b-12d3-a456-426614174000 \
	SECRET_KEY_BASE="dev" \
	CLUSTER_POSTGRES="true" \
	DB_POOL_SIZE="5" \
	METRICS_DISABLED="false" \
	ERL_AFLAGS="-kernel shell_history enabled +zdbbl 2097151" \
	iex --name node1@127.0.0.1 --cookie cookie -S mix run --no-halt

dev.node2:
	PORT=4001 \
	MIX_ENV=dev \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	REGION=eu \
	SECRET_KEY_BASE="dev" \
	CLUSTER_POSTGRES="true" \
	PROXY_PORT_SESSION="5442" \
	PROXY_PORT_TRANSACTION="6553" \
	NODE_IP=localhost \
	ERL_AFLAGS="-kernel shell_history enabled" \
	iex --name node2@127.0.0.1 --cookie cookie -S mix phx.server

dev.node3:
	PORT=4002 \
	MIX_ENV=dev \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	REGION=eu \
	SECRET_KEY_BASE="dev" \
	CLUSTER_POSTGRES="true" \
	PROXY_PORT_SESSION="5443" \
	PROXY_PORT_TRANSACTION="6554" \
	ERL_AFLAGS="-kernel shell_history enabled" \
	iex --name node3@127.0.0.1 --cookie cookie -S mix phx.server

db_migrate:
	mix ecto.migrate --prefix _supavisor --log-migrator-sql

db_start:
	docker-compose -f ./docker-compose.db.yml up

db_stop:
	docker-compose -f ./docker-compose.db.yml down --remove-orphans

db_rebuild:
	make db_stop
	docker-compose -f ./docker-compose.db.yml build
	make db_start

PGBENCH_USER ?= postgres.sys
PGBENCH_PORT ?= 6543
PGBENCH_RATE ?= 5000
PGBENCH_DURATION ?= 60
PGBENCH_CLIENTS ?= 1000

pgbench_init:
	PGPASSWORD=postgres pgbench -i -h 127.0.0.1 -p 6432 -U postgres -d postgres

pgbench_short:
	PGPASSWORD=postgres pgbench -M extended --transactions 5 --jobs 4 --client 1 -h localhost -p 6543 -U postgres.sys postgres

pgbench_long:
	PGPASSWORD=postgres pgbench -M extended --transactions 100 --jobs 10 --client 60 -h localhost -p 7654 -U transaction.localhost postgres

pgbench:
	PGPASSWORD="postgres" pgbench \
		   postgres://${PGBENCH_USER}@localhost:${PGBENCH_PORT}/postgres?sslmode=disable \
		   -Srn -T ${PGBENCH_DURATION} \
		   -j 8 -c ${PGBENCH_CLIENTS} \
		   -P 10 -M extended \
		   --rate ${PGBENCH_RATE}

clean:
	rm -rf _build && rm -rf deps

dev_release:
	mix deps.get && mix compile && mix release supavisor

dev_up:
	rm -rf _build/dev/lib/supavisor && \
	MIX_ENV=dev mix compile && \
	mix release supavisor

dev_start_rel:
	MIX_ENV=dev \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	REGION=eu \
	FLY_ALLOC_ID=111e4567-e89b-12d3-a456-426614174000 \
	SECRET_KEY_BASE="dev" \
	CLUSTER_POSTGRES="true" \
	DB_POOL_SIZE="5" \
	_build/prod/rel/supavisor/bin/supavisor start_iex

# rm -rf _build/prod && \

prod_rel:
	MIX_ENV=prod METRICS_DISABLED=true mix compile && \
	MIX_ENV=prod METRICS_DISABLED=true mix release supavisor

prod_start_rel:
	MIX_ENV=prod \
	NODE_NAME="localhost" \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	REGION=eu \
	FLY_ALLOC_ID=111e4567-e89b-12d3-a456-426614174000 \
	SECRET_KEY_BASE="dev" \
	CLUSTER_POSTGRES="true" \
	DB_POOL_SIZE="5" \
	_build/prod/rel/supavisor/bin/supavisor start_iex

prod_start_rel2:
	MIX_ENV=prod \
	NODE_NAME=node2 \
	PORT=4001 \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	REGION=eu \
	SECRET_KEY_BASE="dev" \
	CLUSTER_POSTGRES="true" \
	PROXY_PORT_SESSION="5442" \
	PROXY_PORT_TRANSACTION="6553" \
	NODE_IP=localhost \
	_build/prod/rel/supavisor/bin/supavisor start_iex
