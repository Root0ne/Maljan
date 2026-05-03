# Task Completion Checklist
Before marking a task as complete:
- [ ] Code follows Python 3.13+ async-first style.
- [ ] Strict type hints added and `make typecheck` passes.
- [ ] Ruff linting (`make lint`) passes with 100 char limit.
- [ ] Tests updated/added and `make test` passes.
- [ ] No emojis added to the code.
- [ ] If adding an agent, registered via `AgentRegistry` and tested.
- [ ] If changing config, updated both `.env.example` and config models.
- [ ] Ensure DI (`ServiceContainer`) is used instead of global state.
