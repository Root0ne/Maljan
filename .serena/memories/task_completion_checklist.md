# Task Completion Checklist
Before marking a task complete, verify:

- [ ] Code follows Python 3.13+ async-first style (all IO is async/await).
- [ ] Strict type hints added and `make typecheck` passes.
- [ ] Ruff lint (`make lint`) and format (`make format-check`) pass at 100 cols.
- [ ] Tests updated/added and `make test` passes. If touching the API/frontend, consider the
      relevant integration / Playwright e2e (`apps/web/e2e/`) tests too.
- [ ] No emojis added to the code.
- [ ] New agent: extends `BaseAnalyst`, registered via `@register_agent("name")`, and tested.
- [ ] Config change: updated `.env.example` + the relevant model (`src/maljan/core/config.py`
      nested OR `apps/api/app/config.py` flat). Never instantiate `Settings()` at import time —
      use `get_settings()`.
- [ ] DI (`ServiceContainer`) used instead of global state / module-level singletons.
- [ ] Schema change: ISR models (`schemas/isr_models.py`, incl. `rule_platforms`) and/or STIX
      models (`schemas/stix_models.py`) and/or `reporting/models.py` (`MalwareReport`) stay consistent;
      add an Alembic migration if a DB column changes.
- [ ] New dependency: added to `pyproject.toml` and `uv sync` run.
- [ ] Graceful degradation preserved for ALL optional components (YARA, Sigma, ATT&CK, LTM, MCP,
      sandbox, narrative, detection signatures, extractors, enrichment).
- [ ] Pipeline node change: mock-mode path still works; state reducers correct; `AnalysisState`
      TypedDict compatibility maintained (incl. new fields: platform, malware_report*, degraded_mode, sandbox_cti).
- [ ] LLM invocation change: agent coroutines stay on the shared persistent event loop
      (`base_agent._get_agent_loop()`); never create/close per-call loops (BUG-04/06).
- [ ] Platform-aware path (Wave 4 + 2026-06-02 narrowing): cascade / detection rules / fp_linter
      keep `state["platform"]` consistent between judge and report nodes; valid values are ONLY
      windows/linux/unknown; entry rejection (`unsupported_os_reason`) must not block legitimate
      Win/Linux samples.
- [ ] New retrieval/heuristic feature: config-gated on `PreprocessingConfig`, fail-safe,
      verdict-neutral (advisory hint), and measured by an `eval_*` harness before default-ON.
      Eval harnesses touching live samples must force `SANDBOX__BACKEND=mock`.
- [ ] Confidence integrity (CONF-INFL-01): degraded runs honour `degraded_mode` + 0.60 cap; do not
      surface inflated cascade-only confidence.
- [ ] Indicator hygiene: new IOC paths respect `agents/_indicator_denylists.py` and the
      judge_postprocess J-02 / fp_linter caps.
