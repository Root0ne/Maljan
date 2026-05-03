# Maljan — Task Completion Checklist

After making any code change, always do the following:

## 1. Run Quality Gates
```bash
# Minimum: lint + format + tests
make ci-check

# Full gate (recommended for significant changes):
make check
```

## 2. Verify Test Suite Stays Green
- Run `uv run pytest tests/ -q` and confirm no failures
- New code should add tests in the appropriate test directory
- Note: test count may have changed since last baseline — always verify zero failures

## 3. Type Check
```bash
uv run mypy src/
```
- Must return: `Success: no issues found in N source files`

## 4. Commit with Conventional Message
```bash
git add -A
git commit -m "type(scope): description"
git push
```

## 5. For Significant Changes: Update Docs
- If architecture changes: update `docs/ARCHITECTURE.md`
- If new TODO items added/completed: update `docs/TODO.md` AND `current_todo.md` (root)
- If new dependencies added: verify they are in `pyproject.toml` dependencies
- If CLI commands added: verify `maljan --help` shows them
- If new MCP server added: document in `architecture_key_points` memory

## Key CI Gates (GitHub Actions)
The CI pipeline in `.github/workflows/ci.yml` runs:
1. `ruff check src/ tests/`
2. `ruff format --check src/ tests/`
3. `mypy src/`
4. `pytest tests/ -q`

All four must pass before merging.

## Active TODO Priorities (from current_todo.md)
Next items to implement (in order):
- **TODO-E** (High): CAPEv2 MCP tool discovery fix in DynamicAnalyst
- **TODO-F** (High): Ghidra MCP few-shot ReAct prompt tuning in StaticAnalyst
- **TODO-G** (Critical): End-to-end ReAct pipeline + `scripts/run_analysis.py`
- **TODO-H** (Critical): Full Sycophancy Detector with cosine embeddings
- **TODO-I** (High): K-S Test adaptive termination
- **TODO-J** (High): Qdrant STIX Store + RAG retrieval
