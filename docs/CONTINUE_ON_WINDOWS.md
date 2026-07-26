# Continuing Maljan on Windows

Quick handoff notes for resuming development after transferring this project to a
Windows machine. (Written 2026-07-13.)

## Current branch & state
- Branch: **`fix/report-content-audit`** (not `main`). `git status` should be clean
  after transfer; run `git log --oneline -8` to see the latest work.
- Just completed: **static-analysis depth restore** (max_steps 8→40, tool-output
  6000, static timeout 1500, `parallel_analysts` default False + revision node
  serialised) — validated E2E (static 3→19 tool calls, zero re-prefill, zero
  timeout). See `docs/academic-article/findings-log.md` (top of Changelog).
- Report-reshaping roadmap: **Phases 1–5 done** (schema, deterministic population,
  Composer, figures). **Phases 6–8 remain**: 6 = HTML/PDF export (WeasyPrint +
  `/reports/{id}/html|pdf` endpoints), 7 = frontend (DownloadBar + new tabs),
  8 = conventions polish.

## Bring the stack up (Windows)
1. **LLM server (host, GPU):** start the local Qwen3.6-35B server with
   `run_llama.ps1` (ik_llama.cpp CUDA build). It must serve an OpenAI-compatible
   endpoint reachable from containers at `http://host.docker.internal:8080/v1`.
2. **Docker Desktop** running, then from the repo root:
   `docker compose -f docker/docker-compose.yml up -d` (adjust path if different).
   Python code under `src/` + `apps/` is bind-mounted — `docker restart
   maljan-worker` picks up Python edits.
3. **`.env`**: copy from `.env.example` and fill secrets. Keep
   `LLM__PARALLEL_ANALYSTS=false` (single-slot local model — see the config.py
   field comment; it is now also the default).
4. **CAPE** (optional, for dynamic analysis): CAPEv2 reachable at
   `host.docker.internal:18000`.

## GitHub
Remote is `https://github.com/Root0ne/Maljan.git`, and the branch is already pushed
— local and origin match, so nothing is stranded on the Linux box.

**Before you push from Windows you must rotate the token.** The old classic token
carried nearly every scope (`admin:org`, `delete_repo`, `workflow`, `user`, …) and
was exposed in a chat transcript, so it has to be deleted rather than reused. Step
by step: `_GITHUB_SETUP.txt` at the **root of the transfer zip** (not committed —
and it no longer contains any token). Short version: delete the old token at
github.com → Settings → Developer settings → Personal access tokens, mint a
fine-grained one scoped to `Root0ne/Maljan` with *Contents: Read and write*, then
`gh auth login` and paste it.

## First things to verify after transfer
- `git log` shows the depth-restore commits (`c856ba4`, `287740c`, + this session).
- `docker compose ... up -d` brings up worker/api/frontend/postgres/redis/qdrant/
  ghidra-mcp/minio.
- `make test` (or `uv run pytest tests/ -q`) — the suite is **fully green**. The 8
  failures this file used to warn about were fixed in the 2026-07-26 audit round
  (two of them turned out to be real bugs, not stale tests: view-decomposition
  dropped every ATT&CK technique ID, and the YARA gate still emitted
  `Maljan_AutoGen_unknown`). Any failure you see on Windows is new — do not
  dismiss it as pre-existing.

## Report export (Phase 6)
`GET /api/v1/reports/{id}/html` and `/pdf` render the full report — A4, numbered
pages, linked contents, and the deterministic SVG figures, which until now were
generated on every run and displayed nowhere. Both come from one document, so
they cannot disagree; `?download=true` on `/html` forces a save instead of
opening inline. The analysis page has matching *↓ PDF report* / *↓ HTML report*
buttons next to Markdown.

Inside Docker this just works — `docker/Dockerfile.backend` installs WeasyPrint's
runtime libraries (`libpango-1.0-0`, `libpangoft2-1.0-0`, `libharfbuzz-subset0`,
`fonts-dejavu-core`). **If you run the backend natively on Windows instead**,
`uv sync` will install the wheel happily and `/pdf` will still return 503,
because WeasyPrint binds to those libraries through ctypes at call time, not at
import. Install the GTK runtime
(<https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer>) and
it resolves. Markdown, HTML and STIX exports need none of this.

## Known follow-ups
- **Multi-chunk + revision-round E2E** still unverified (the single-chunk run
  validated per-chunk depth; revision serialisation is covered by the
  `test_analyst_parallelism.py` gather-spy unit test). Run a real PE that splits
  into ≥8 chunks and produces analyst dissent to confirm.
- **Ghidra `load_program` on large binaries** can be slow — auto-analysis of a
  3.8 MB PE took minutes; budget for it (per-chunk Ghidra re-analysis is a known
  cost). No confirmed hang, but watch it.
