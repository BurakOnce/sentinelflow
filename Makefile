SHELL := /bin/sh
-include .env
export CLICKHOUSE_USER CLICKHOUSE_PASSWORD CLICKHOUSE_DB

ALL_PROFILES := core streaming batch observability
PROFILES ?= $(ALL_PROFILES)
SERVICE ?=
SCENARIO ?= password_spraying
SIM_ARGS ?= --duration 6h --attack all
DEMO_BACKFILL ?= 6h
DEMO_LIVE ?= 3m

COMPOSE := docker compose
COMPOSE_UP := $(COMPOSE) $(addprefix --profile ,$(PROFILES))
COMPOSE_ALL := $(COMPOSE) $(addprefix --profile ,$(ALL_PROFILES))
SIMULATOR := $(COMPOSE_ALL) run --rm simulator run

.PHONY: help install data-dirs up wait down logs ps build simulate attack demo summary \
	scenarios rules test test-spark test-e2e lint format dbt clean

help:
	@echo "install     sync the local environment with all extras"
	@echo "up          start services and wait until healthy (PROFILES=\"$(ALL_PROFILES)\")"
	@echo "down        stop all services"
	@echo "logs        follow logs (SERVICE=name to filter)"
	@echo "ps          list services"
	@echo "build       build local images"
	@echo "simulate    backfill simulated logs from the host (SIM_ARGS=...)"
	@echo "attack      replay one attack into the last 15 minutes (SCENARIO=name)"
	@echo "demo        start everything, run traffic and attacks, print a summary"
	@echo "summary     wait for the pipeline, build dbt models and print efficacy"
	@echo "redetect    reprocess all normalized events with the current rules"
	@echo "scenarios   list attack scenarios"
	@echo "rules       validate detection rules and refresh the dbt rule catalogue"
	@echo "test        run unit tests"
	@echo "test-spark  run the full test suite inside the spark image"
	@echo "test-e2e    run the end to end test against a running stack"
	@echo "lint        run ruff and mypy"
	@echo "format      apply ruff formatting and fixes"
	@echo "dbt         run dbt build against the local ClickHouse"
	@echo "clean       stop services and remove volumes"

.env:
	cp .env.example .env

install:
	uv sync --all-extras

data-dirs:
	mkdir -p data/logs data/labels data/geoip

up: .env data-dirs
	$(COMPOSE_UP) up -d --build
	@$(MAKE) --no-print-directory wait

wait:
	@echo "waiting for services to become healthy"
	@for attempt in $$(seq 1 90); do \
		pending=$$($(COMPOSE_UP) ps --format '{{.Service}} {{.Health}}' | grep -E 'starting|unhealthy' || true); \
		if [ -z "$$pending" ]; then echo "all services healthy"; exit 0; fi; \
		sleep 5; \
	done; \
	$(COMPOSE_UP) ps; echo "services did not become healthy"; exit 1

down:
	$(COMPOSE_ALL) down

logs:
	$(COMPOSE_ALL) logs -f --tail=200 $(SERVICE)

ps:
	$(COMPOSE_ALL) ps -a

build: .env
	$(COMPOSE_ALL) build

simulate: data-dirs
	uv run sentinelflow-sim run $(SIM_ARGS)

attack:
	$(SIMULATOR) --mode backfill --duration 15m --no-baseline --users 200 \
		--seed $$(date +%s) --attack $(SCENARIO)

demo: up
	$(SIMULATOR) --mode backfill --duration $(DEMO_BACKFILL) --attack all --seed 7
	$(SIMULATOR) --mode realtime --duration $(DEMO_LIVE) --seed 8 \
		--attack ssh_bruteforce:0.5 --attack port_scan:0.3 --attack web_attack:0.3
	$(COMPOSE_ALL) exec -T dagster-webserver sentinelflow-demo

summary:
	$(COMPOSE_ALL) exec -T dagster-webserver sentinelflow-demo

redetect:
	$(COMPOSE_ALL) stop spark-detect
	$(COMPOSE_ALL) exec -T minio sh -c 'mc alias set lake http://localhost:9000 "$$MINIO_ROOT_USER" 		"$$MINIO_ROOT_PASSWORD" > /dev/null && mc rm -r --force lake/checkpoints/detect || true'
	$(COMPOSE_ALL) exec -T clickhouse clickhouse-client --user "$(CLICKHOUSE_USER)" 		--password "$(CLICKHOUSE_PASSWORD)" -d "$(CLICKHOUSE_DB)" 		--multiquery -q "TRUNCATE TABLE alerts; TRUNCATE TABLE detector_state"
	$(COMPOSE_ALL) up -d spark-detect

scenarios:
	uv run sentinelflow-sim scenarios

rules:
	uv run sentinelflow-rules validate
	uv run sentinelflow-rules export

test:
	uv run pytest -m "not integration"

test-spark:
	docker run --rm -v "$$(pwd):/src" -w /src -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
		sentinelflow/spark:local sh -c "uv sync --frozen --all-extras -q && uv run pytest -m 'not integration'"

test-e2e:
	uv run pytest -m integration -v

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

format:
	uv run ruff check --fix .
	uv run ruff format .

dbt:
	cd transform && uv run dbt build --profiles-dir .

clean:
	$(COMPOSE_ALL) down -v --remove-orphans
