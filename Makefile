.PHONY: dev
dev:
	MIX_ENV=dev ERL_AFLAGS="-kernel shell_history enabled" iex -S mix phx.server

db_start:
	docker-compose -f ./dev/docker-compose.db.yml up

db_stop:
	docker-compose -f ./dev/docker-compose.db.yml down  --remove-orphans

db_rebuild:
	make db_stop
	docker-compose -f ./dev/docker-compose.db.yml build
	docker-compose -f ./dev/docker-compose.db.yml up --force-recreate --build