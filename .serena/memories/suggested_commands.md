# Suggested Commands

> Refreshed 2026-07-05. Project currently mounted at `/run/media/user/Kingston/Projects/Maljan`
> (Linux); previously developed on Windows (`d:\Projects\Maljan` — run_llama.ps1/run_worker.ps1
> are PowerShell).

## Setup
- `uv sync`; `uv run pre-commit install`; or `make setup`.

## Testing / Quality Gates
- `make test` / `make test-unit` (79 modules) / `make test-integration` (6) / `make test-qdrant`
- `make lint` / `make format` / `make format-check` / `make typecheck`
- `make check` (full gate) / `make ci-check` (fast, no typecheck) / `make pre-commit-run`

## CLI Analysis (standalone)
- `uv run maljan analyze <file_hash> --provider openai`; `--mock` for fixture mode.
- Local single-slot llama-server: `LLM__PARALLEL_ANALYSTS=false` (sequential analysts) and
  `LLM__OPENAI__DISABLE_THINKING=true` (REQUIRED for local Qwen3 — suppresses <think>).
- Non-Win/Linux samples are rejected at entry (`UnsupportedSampleError`).

## Local llama-server (`run_llama.ps1`, ik_llama.cpp)
`llama-server.exe -m Qwen3.6-35B-A3B-IQ3_K_R4.gguf -ngl 99 --n-cpu-moe 36 -fa on -c 131072
-ctk q8_0 --jinja --host 127.0.0.1 --port 8080` — context deliberately 131072 (256k + quantized
V-cache wedged the server); V-cache f16 (no `-ctv`), K-cache q8_0.

## Docker (8 services)
- `cd docker && docker compose up --build -d`; logs via `docker logs maljan-api|maljan-worker`.

## Sandbox (CAPE remote VM — `docs/CAPE2_REMOTE_VM_SETUP.md`)
- Default `SANDBOX__BACKEND=mock`. Live: CAPEv2 on an Ubuntu VM, REST at
  `SANDBOX__CAPE2_BASE_URL=http://<VM_IP>:8000` (+`SANDBOX__CAPE2_API_TOKEN`,
  timeout 1200 / poll 15 recommended). Optional CAPE MCP over HTTP:
  VM runs `python scripts/cape_mcp_wrapper.py --transport http --host 0.0.0.0 --port 9004`,
  Windows side `MCP__CAPE__ENABLED=true MCP__CAPE__TRANSPORT=http MCP__CAPE__URL=http://<VM_IP>:9004/mcp/`.

## Database / Migrations (still 5 migrations)
- `cd apps/api && uv run alembic upgrade head`; autogenerate for new ones.
- `docker exec maljan-postgres psql -U maljan -d maljan -c "\dt"`.

## Reporting / Enrichment (API)
- `GET /api/v1/reports/{id}/full|markdown|iocs|signatures/{kind}`; `POST /reports/{id}/enrich`.
- `/iocs?kind=` accepts hash/domain/ip/url/user_agent/ja3/ja3s.

## Frontend (apps/web)
- `npm run dev` / `npm run build` / `npm run lint`; `npx playwright test`.

## Benchmarks & Eval harnesses (see `mem:evaluation_research`)
- `make benchmark`; `make prepare-tram`+`benchmark-tram`; `make prepare-attck`+`benchmark-attck`.
- Measurement harnesses run directly (NOT pytest): `uv run python tests/evaluation/eval_temporal_drift.py`
  (has `--dry-run`, LLM health check, checkpoint/resume), `eval_narrative_quality.py`,
  `eval_hint_ablation.py`, `eval_view_decomposition.py`, `eval_category_inference.py`,
  `eval_technique_mapping.py`, `eval_autocorrect_ablation.py`, `eval_function_rag.py`,
  `eval_family_rag_retrieval.py`, `run_family_rag_ab.py` (forces SANDBOX__BACKEND=mock).

## RAG knowledge-base builders (offline operator tools)
- `uv run python scripts/build_family_feature_kb.py --samples-dir ... | --csv ...` ->
  `data/family_fingerprints_v1.json` (U3).
- `uv run python scripts/build_attck_case_kb.py --qdrant-url ... | --mabel-csv ...` ->
  `data/attck_case_corpus_v1.json` (U2).
- Runtime toggles: `PREPROCESSING__USE_FAMILY_FEATURE_RAG` / `PREPROCESSING__USE_ATTCK_CASE_RAG`
  (both default false — A/B showed no measurable TTP gain).

## Cache & Index
- ATT&CK index pre-build: `uv run python -c "from maljan.memory.attck_validator import ATTCKValidator; ATTCKValidator.get_instance()"`
  (backend selector `PREPROCESSING__ATTCK_INDEX_BACKEND=hybrid|tfidf|semantic`).
- Qdrant LTM check: collection `maljan_cases_v2`; function hashes `maljan_function_hashes_v1`.

## MCP Servers
- `python network-mcp/server.py`; `python threatintel-mcp/server.py`;
  `python scripts/cape_mcp_wrapper.py` (stdio/sse/streamable-http via `--transport`).
- Ghidra MCP: Docker service (HTTP :8089), pinned v5.6.0 + patches in
  `docs/migration/ghidra-mcp-patches/`.

## Worker (local dev, from apps/api/)
- `uv run arq app.worker.analysis_worker.WorkerSettings` (max_jobs=1, job_timeout=3600)
- `uv run arq app.worker.enrich_worker.WorkerSettings`
