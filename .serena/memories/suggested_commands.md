# Maljan — Suggested Commands

All commands run from the project root: `d:\MyCodes\Maljan`

## Package Management (uv)
```powershell
uv sync                          # Install all dependencies
uv add <package>                 # Add a runtime dependency
uv add --dev <package>           # Add a dev dependency
uv run <command>                 # Run any command in the venv
```

## Quality Gates (MUST run after every code change)
```powershell
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
```powershell
uv run pytest tests/ -q                          # All tests
uv run pytest tests/unit/ -v                     # Unit only, verbose
uv run pytest tests/unit/test_foo.py -v          # Single file
uv run pytest -k "test_name" -v                  # Filter by name
uv run pytest tests/ -q --tb=short              # Short traceback

# Qdrant tests (requires running Qdrant on :6333)
make test-qdrant
```

## Benchmark
```powershell
make benchmark
# OR
set PYTHONPATH=src && uv run python -m tests.evaluation.benchmark_suite
# OR (after pip install)
maljan benchmark
maljan benchmark --fixtures-dir tests/evaluation/fixtures/ --format json
```

## CLI
```powershell
uv run maljan analyze <sample_file>
uv run maljan analyze <sample_file> --provider openai --model gpt-4o
uv run maljan info
uv run maljan benchmark
```

## Git
```powershell
git status
git add -A
git commit -m "type(scope): message"
git push
git log --oneline -10
```

## Pre-commit
```powershell
make setup               # Install pre-commit hooks
make pre-commit-run      # Run all hooks manually
```

## Windows-specific Notes
- Use `Get-ChildItem` instead of `ls`
- Use `Move-Item` instead of `mv`
- Use `Test-Path` to check file existence
- PowerShell uses `;` not `&&` for chaining commands
- `set PYTHONPATH=src` for Makefile benchmark target
