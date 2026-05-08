.PHONY: test lint typecheck format setup check ci-check pre-commit-run benchmark prepare-tram benchmark-tram prepare-attck benchmark-attck docker-build docker-up docker-down docker-logs rebuild-ghidra

test:
	uv run pytest tests/ -q

test-verbose:
	uv run pytest tests/ -v

test-qdrant:
	QDRANT_URL=http://localhost:6333 uv run pytest tests/unit/test_qdrant_store.py -v

test-unit:
	uv run pytest tests/unit/ -q

test-integration:
	uv run pytest tests/integration/ -q

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

format-check:
	uv run ruff format --check src/ tests/

typecheck:
	uv run mypy src/

# Full local quality gate (mirrors CI)
check: lint format-check typecheck test

# Quick gate without typecheck (fast feedback loop)
ci-check: lint format-check test

setup:
	uv sync
	uv run pre-commit install

pre-commit-run:
	uv run pre-commit run --all-files

benchmark:
	set PYTHONPATH=src && uv run python -m tests.evaluation.benchmark_suite

prepare-tram:
	uv run python scripts/prepare_tram_dataset.py

benchmark-tram:
	set PYTHONPATH=src && uv run python -m tests.evaluation.benchmark_suite --fixtures-dir tests/evaluation/ground_truth/tram

prepare-attck:
	uv run python scripts/prepare_attck_malware_fixtures.py

benchmark-attck:
	set PYTHONPATH=src && uv run python -m tests.evaluation.benchmark_suite --fixtures-dir tests/evaluation/ground_truth/attck_malware

# ── Docker Orchestration ───────────────────────────────────────────

docker-build:
	cd docker && set POSTGRES_PORT=5433 && docker compose build

docker-up:
	cd docker && set POSTGRES_PORT=5433 && docker compose up -d

docker-down:
	cd docker && docker compose down

docker-logs:
	cd docker && docker compose logs -f

# ── Ghidra MCP Manager ─────────────────────────────────────────────

ghidra-status:
	uv run python scripts/ghidra_manager.py status

ghidra-sync:
	uv run python scripts/ghidra_manager.py sync

ghidra-build:
	uv run python scripts/ghidra_manager.py build

ghidra-watch:
	uv run python scripts/ghidra_manager.py watch

# Legacy alias
rebuild-ghidra: ghidra-build
