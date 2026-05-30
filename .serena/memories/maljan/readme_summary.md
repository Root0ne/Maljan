# Maljan README Summary

> Refreshed 2026-05-30. Corrects dead doc references from the previous version.

## Purpose
Maljan is a production-grade malware analysis platform using adversarial multi-agent debate
(LangGraph) to classify samples as Malware/Benign/Suspicious. It grounds verdicts in deterministic
detection (YARA, Sigma) + ATT&CK validation, then produces a comprehensive `MalwareReport` and a
STIX 2.1 bundle with per-claim confidence.

## README (root `README.md`) structure
1. Header — CI / Python 3.13 / "tests 800+ passed" badges (the test badge is a static label).
2. Key Capabilities table.
3. Architecture — ASCII diagram + ISR + DI/AgentRegistry notes.
4. Quick Start — standalone CLI + Docker full-stack + ATT&CK cache pre-build.
5. Project Structure — tree of `src/maljan/`, `apps/api/`, `apps/web/`.
6. Web UI / API endpoints / Development / Configuration / Design Principles.

## Documentation map (CORRECTED)
- There is **no root `AGENTS.md`** and **no `docs/ARCHITECTURE.md`** (the previous memory referenced
  both — they do not exist). Deep-dive operational docs now live at:
  - `docs/operator-runbook.md` — operator gotchas / runbook (actively updated each Wave).
  - `docs/triage_api/` — Recorded Future Triage Cloud API reference (supports `loaders/triage_client.py`).
  - `docs/research/` — research reports / paper drafts.
  - `apps/web/AGENTS.md` and `apps/web/CLAUDE.md` — frontend-specific agent docs (these DO exist).
- Config reference: `.env.example` (root) and `apps/api/.env.example`.

## Web UI (apps/web — see `mem:frontend_web_app`)
- Next.js 16 / React 19 / Tailwind 4 App Router. Auth pages + dashboard / jobs / audit / settings.
- The analysis detail view (`analysis/[id]/`) now has ~18 tabs: identity, static, dynamic, network,
  persistence, capabilities, ttps, attribution, signatures, rules, stix, timeline, defense, live,
  pipeline, agents (plus the overview page). Playwright e2e exists.

## Design Principles
No hallucinated TTPs (ATT&CK validation + judge_postprocess), no sycophancy (cosine + Devil's
Advocate), graceful degradation everywhere, protocol-based extensibility, platform-aware filtering,
confidence integrity (degraded-mode cap).
