.PHONY: test lint typecheck format setup check ci-check pre-commit-run benchmark prepare-tram benchmark-tram prepare-attck benchmark-attck prepare-api-db docker-build docker-up docker-down docker-logs dev-up dev-down dev-logs fe-rebuild worker-restart rebuild-ghidra

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

# Everything Python in the repo, not just the library. `src/ tests/` left the
# FastAPI app, the arq worker, the MCP sidecars and scripts/ outside the gate:
# pre-commit still ran ruff over them because it works on staged files, so the
# only way to drift was to go a long time without being staged — which is
# exactly what network-mcp/server.py did, unformatted since 8e3370c and unnoticed
# because nothing ever looked at the whole tree.
PY_SOURCES = src/ tests/ apps/api/ network-mcp/ threatintel-mcp/ scripts/

lint:
	uv run ruff check $(PY_SOURCES)

format:
	uv run ruff check --fix $(PY_SOURCES)
	uv run ruff format $(PY_SOURCES)

format-check:
	uv run ruff format --check $(PY_SOURCES)

# apps/api/ included deliberately: the worker and the report service hold this
# branch's most consequential fixes and had never once been type-checked, in the
# Makefile or in pre-commit. It costs ~51 extra files and found one missing
# annotation.
typecheck:
	uv run mypy src/ apps/api/

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

# Regenerate the Windows API behaviour map and the API->ATT&CK map. The curated
# lists live in the script, not the JSON — the JSON is the artifact. Validates
# every technique ID against data/attck_valid_ids.json and refuses to write on
# any mismatch, so a typo fails loudly here rather than silently never firing.
prepare-api-db:
	uv run python scripts/build_api_capability_db.py

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

# ── Development loop ───────────────────────────────────────────────
# The production stack bakes the frontend into an image and runs the worker
# under plain `arq`, so NEITHER picks up a source edit on its own. That cost
# real debugging time (a live analysis ran the previous worker build; the
# deployed UI was a stale bundle for a whole session), so the two ways out are
# spelled out here rather than left to be rediscovered.

# Live source for both: `next dev` for the frontend, watchfiles-supervised arq
# for the worker. Use this while developing.
dev-up:
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml up -d

dev-down:
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml down

dev-logs:
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml logs -f

# On the production stack, these are the two commands that make an edit real.
fe-rebuild:
	cd docker && docker compose build frontend && docker compose up -d --no-deps frontend

worker-restart:
	docker restart maljan-worker

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

# The paper. Facts first, always: build_paper.py refuses to run against a
# paper_facts.json older than any result it summarises, so this ordering is not
# a convenience — the reverse order fails loudly, which is the point.
.PHONY: paper facts
facts:
	.venv/bin/python tests/evaluation/paper_facts.py

paper: facts
	.venv/bin/python tests/evaluation/make_paper_figures.py
	.venv/bin/python docs/academic-article/paper/build_paper.py
