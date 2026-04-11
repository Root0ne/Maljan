.PHONY: test lint typecheck format setup check

test:
	uv run pytest -v

lint:
	uv run ruff check .

format:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run mypy src/ tests/

check: lint typecheck test

setup:
	uv sync
	uv pip install pre-commit
	~/.local/bin/uv run pre-commit install
