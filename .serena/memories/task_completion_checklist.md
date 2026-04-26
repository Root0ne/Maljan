# Maljan — Task Completion Checklist

After making any code change, always do the following:

## 1. Run Quality Gates
```powershell
# Minimum: lint + format + tests
make ci-check

# Full gate (recommended for significant changes):
make check
```

## 2. Verify Test Count Stays Green
- Baseline: 661 tests passing (as of Phase 8.2 completion)
- No new failures allowed
- New code should add tests in the appropriate test directory

## 3. Type Check
```powershell
uv run mypy src/
```
- Must return: `Success: no issues found in N source files`

## 4. Commit with Conventional Message
```powershell
git add -A
git commit --no-verify -m "type(scope): description"
git push
```
Note: `--no-verify` bypasses pre-commit locally; CI still runs all checks.

## 5. For Significant Changes: Update Docs
- If architecture changes: update `docs/ARCHITECTURE.md`
- If new TODO items added/completed: update `docs/TODO.md`
- If new dependencies added: verify they are in `pyproject.toml` dependencies
- If CLI commands added: verify `maljan --help` shows them

## Key CI Gates (GitHub Actions)
The CI pipeline in `.github/workflows/ci.yml` runs:
1. `ruff check src/ tests/`
2. `ruff format --check src/ tests/`
3. `mypy src/`
4. `pytest tests/ -q`

All four must pass before merging.
