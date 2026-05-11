# AGENTS.md Update Status (Latest)

## Changes Applied
1. **Dockerfile.backend**: `python:3.12-slim` → `python:3.13-slim` (matches pyproject.toml `requires-python = ">=3.13, <3.14"`)
2. **AGENTS.md Docker Services**: `python:3.12-slim` → `python:3.13-slim`
3. **AGENTS.md Ollama models**: `qwen2.5-coder:7b` / `llama3.1:70b` → `qwen3.5:9b` (matches `src/maljan/core/config.py` defaults)
4. **AGENTS.md Recent Changes**: Updated to reflect current state (Docker 8 services, Python 3.13 pin, Pipeline tab, Worker fixes, 824 passed / 3 skipped)
5. **AGENTS.md Active Issues**: Removed resolved items (MCP cleanup, re-enable agents, qwen2.5-coder validation). Added current gaps (structured output reliability, rate limiting, frontend E2E tests, facade tests)
