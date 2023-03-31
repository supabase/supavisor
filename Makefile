help:
	@make -qpRr | egrep -e '^[a-z].*:$$' | sed -e 's~:~~g' | sort

.PHONY: dev
dev:
	MIX_ENV=dev \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	FLY_REGION=eu \
	FLY_ALLOC_ID=111e4567-e89b-12d3-a456-426614174000 \
	ERL_AFLAGS="-kernel shell_history enabled" \
	iex --name node1@127.0.0.1 --cookie cookie -S mix run --no-halt

dev.node2:
	PROXY_PORT=7655 \
	PORT=4001 \
	MIX_ENV=dev \
	VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" \
	API_JWT_SECRET=dev \
	METRICS_JWT_SECRET=dev \
	FLY_REGION=usa \
	FLY_ALLOC_ID=222e4567-e89b-12d3-a456-426614174000 \
	ERL_AFLAGS="-kernel shell_history enabled" \
	iex --name node2@127.0.0.1 --cookie cookie -S mix phx.server	

dev_cli:
	MIX_ENV=dev mix release supavisor_cli

db_migrate:
	mix ecto.migrate --prefix supavisor --log-migrator-sql

db_start:
	docker-compose -f ./dev/docker-compose.db.yml up

db_stop:
	docker-compose -f ./dev/docker-compose.db.yml down --remove-orphans

db_rebuild:
	make db_stop
	docker-compose -f ./dev/docker-compose.db.yml build
	make db_start

pgbench_init:
	PGPASSWORD=postgres pgbench -i -h 127.0.0.1 -p 6432 -U postgres -d postgres

pgbench_short:
	PGPASSWORD=postgres pgbench -M extended --transactions 5 --jobs 4 --client 1 -h localhost -p 7654 -U postgres.localhost postgres

pgbench_long:
	PGPASSWORD=postgres pgbench -M extended --transactions 100 --jobs 10 --client 60 -h localhost -p 7654 -U postgres.localhost postgres
