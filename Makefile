.PHONY: dev
dev:
	MIX_ENV=dev VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" API_JWT_SECRET=dev ERL_AFLAGS="-kernel shell_history enabled" iex --name node1@127.0.0.1 --cookie cookie -S mix phx.server

dev.node2:
	PROXY_PORT=7655 PORT=4001 MIX_ENV=dev VAULT_ENC_KEY="aHD8DZRdk2emnkdktFZRh3E9RNg4aOY7" API_JWT_SECRET=dev ERL_AFLAGS="-kernel shell_history enabled" iex --name node2@127.0.0.1 --cookie cookie -S mix phx.server	

db_migrate:
	mix ecto.migrate --prefix pgedge --log-migrator-sql

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
