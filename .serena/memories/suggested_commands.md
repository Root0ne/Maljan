# Maljan — Suggested Commands

All commands run from the project root: `/media/user/Kingston1/MyCodes/Maljan`

## Package Management (uv)
```bash
uv sync                          # Install all dependencies
uv add <package>                 # Add a runtime dependency
uv add --dev <package>           # Add a dev dependency
uv run <command>                 # Run any command in the venv
```

## Quality Gates (MUST run after every code change)
```bash
# Full gate (lint + format-check + typecheck + test) — mirrors CI
make check

# Quick gate (lint + format-check + test, no mypy)
make ci-check

# Individual steps
make lint             # ruff check src/ tests/
make format           # ruff check --fix + ruff format
make format-check     # ruff format --check (CI mode)
make typecheck        # mypy src/
make test             # pytest tests/ -q
make test-unit        # pytest tests/unit/ -q
make test-integration # pytest tests/integration/ -q
```

## Testing
```bash
uv run pytest tests/ -q                          # All tests
uv run pytest tests/unit/ -v                     # Unit only, verbose
uv run pytest tests/unit/test_foo.py -v          # Single file
uv run pytest -k "test_name" -v                  # Filter by name
uv run pytest tests/ -q --tb=short              # Short traceback

# Qdrant tests (requires running Qdrant on :6333)
make test-qdrant
```

## Benchmark
```bash
make benchmark
# OR
PYTHONPATH=src uv run python -m tests.evaluation.benchmark_suite
# OR (after install)
maljan benchmark
maljan benchmark --fixtures-dir tests/evaluation/fixtures/ --format json
```

## CLI
```bash
uv run maljan analyze <sample_file>
uv run maljan analyze <sample_file> --provider openai --model gpt-4o
uv run maljan info
uv run maljan benchmark
```

## MCP Servers (local dev)
```bash
# NetworkMCP server
uv run python network-mcp/server.py

# ThreatIntelMCP server
uv run python threatintel-mcp/server.py
```

## Git
```bash
git status
git add -A
git commit -m "type(scope): message"
git push
git log --oneline -10
```

## Pre-commit
```bash
make setup               # Install pre-commit hooks
make pre-commit-run      # Run all hooks manually
```

## OS Notes (Linux)
- Project runs on Linux (WSL path `.venv-wsl` exists alongside `.venv`)
- Use `ls`, `mv`, `test -f` etc. (not PowerShell equivalents)
- `PYTHONPATH=src` prefix for direct module runs
