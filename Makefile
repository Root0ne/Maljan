.PHONY: test lint typecheck format setup check ci-check pre-commit-run

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
