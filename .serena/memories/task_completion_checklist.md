# Task Completion Checklist
Before marking a task as complete, verify:

- [ ] Code follows Python 3.13+ async-first style (all IO is async/await).
- [ ] Strict type hints added and `make typecheck` passes.
- [ ] Ruff linting (`make lint`) passes with 100 char limit.
- [ ] Ruff formatting (`make format-check`) passes.
- [ ] Tests updated/added and `make test` passes.
- [ ] No emojis added to the code.
- [ ] If adding a new agent: extends `BaseAnalyst`, registered via `@register_agent("name")`, and tested.
- [ ] If changing config: updated both `.env.example` and relevant config model(s) in `src/maljan/core/config.py` or `apps/api/app/config.py`.
- [ ] Ensure DI (`ServiceContainer`) is used instead of global state or module-level singletons.
- [ ] If modifying schemas: ISR models in `src/maljan/schemas/isr_models.py` and/or STIX models in `src/maljan/schemas/stix_models.py` are consistent.
- [ ] If adding new dependencies: added to `pyproject.toml` and ran `uv sync`.
- [ ] Graceful degradation preserved: optional components (YARA, Sigma, ATT&CK validator, LTM, MCP) must not crash pipeline on failure.
- [ ] If modifying pipeline nodes: mock mode path still works, state reducers are correct, and `AnalysisState` TypedDict compatibility maintained.
- [ ] If modifying LLM invocation: ReAct tool loop thread isolation preserved (avoid nest_asyncio/anyio cancel scope issues).
