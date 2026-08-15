SHELL := /bin/bash

.PHONY: init config build up down reset logs ps test verify verify-static verify-unit verify-live-safe verify-scanner-live verify-response-live

init:
	@test -f .env || (cp .env.example .env && \
		python3 -c 'from functools import reduce; import os, secrets; from pathlib import Path; p=Path(".env"); replacements={"replace-with-a-long-local-development-password":secrets.token_urlsafe(32),"replace-with-at-least-32-random-characters":secrets.token_urlsafe(48),"replace-with-a-different-32-character-random-token":secrets.token_urlsafe(48),"replace-with-docker-socket-gid":str(os.stat("/var/run/docker.sock").st_gid)}; p.write_text(reduce(lambda value, item: value.replace(*item), replacements.items(), p.read_text(encoding="utf-8")), encoding="utf-8")' && \
		chmod 0600 .env && echo "Created .env with separate local credentials and the Docker socket GID.")

config:
	docker compose config --quiet

build:
	docker compose build backend collector telemetry responder scanner

up:
	docker compose up --detach --build --wait

ps:
	docker compose ps

logs:
	docker compose logs --follow --tail=100

down:
	docker compose down

reset:
	docker compose down --volumes --remove-orphans

verify:
	./scripts/verify_all.sh all

verify-static:
	./scripts/verify_all.sh static

verify-unit:
	./scripts/verify_all.sh unit

verify-live-safe:
	./scripts/verify_all.sh live-safe

verify-scanner-live:
	./scripts/verify_all.sh scanner-live

# DISRUPTIVE: requires PORYGON_RESPONSE_EXECUTION_MODE=live in .env and may
# pause or stop the disposable Phase 7 target. It is never part of `make verify`.
verify-response-live:
	./scripts/verify_phase7.sh

test: verify-unit
