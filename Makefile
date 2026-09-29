# zeek-detection-pack developer and lab targets.
PYTHON ?= python3
COMPOSE ?= docker compose
IMAGE ?= zeek-detection-pack:local
# Lab containers write ./lab/out as the invoking user.
export ZDP_UID ?= $(shell id -u)
export ZDP_GID ?= $(shell id -g)

.DEFAULT_GOAL := help
.PHONY: help install lint typecheck test metrics gates fixtures \
        fixtures-check check image lab lab-demo lab-down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install the package with development dependencies
	$(PYTHON) -m pip install -e ".[dev]"

lint: ## ruff lint + format check
	ruff check .
	ruff format --check .

typecheck: ## mypy --strict
	mypy --strict zdp/

test: ## Unit + system tests with coverage
	$(PYTHON) -m pytest tests --cov=zdp --cov-report=term

metrics: ## Run the harness over the fixtures → metrics.json + reports/
	$(PYTHON) -m zdp.harness --fixtures fixtures --out metrics.json --reports reports

gates: metrics ## Check metrics.json against quality_gates.yaml
	$(PYTHON) tools/check_gates.py metrics.json quality_gates.yaml

fixtures: ## Regenerate the deterministic fixtures
	$(PYTHON) tools/gen_fixtures.py

fixtures-check: ## Fail if committed fixtures differ from the generator output
	$(PYTHON) tools/gen_fixtures.py --check

check: lint typecheck test gates fixtures-check ## Everything CI runs (except containers)

image: ## Build the analyzer image
	docker build -f docker/Dockerfile -t $(IMAGE) .

lab: ## Start the Docker lab (zeek → analyzer, plus the fixture harness)
	mkdir -p lab/logs lab/out pcaps
	$(COMPOSE) up

lab-demo: ## Seed ./pcaps with the synthetic demo capture, then start the lab
	mkdir -p lab/logs lab/out pcaps
	$(PYTHON) tools/gen_demo_pcap.py --out pcaps/zdp-demo.pcap
	$(COMPOSE) up

lab-down: ## Stop the lab and remove its containers
	$(COMPOSE) down --remove-orphans

clean: ## Remove generated runtime output
	rm -rf metrics.json reports/*.md.tmp out lab .pytest_cache .mypy_cache .ruff_cache .coverage
	find reports -name '*.md' ! -name README.md ! -name false_positives.md -delete
