# Maljan README Summary

> Refreshed 2026-07-05 (content check 2026-05-30 + June doc-map corrections).

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
- There is **no root `AGENTS.md`** and **no `docs/ARCHITECTURE.md`**. Deep-dive docs live at:
  - `docs/CAPE2_REMOTE_VM_SETUP.md` — CAPE remote-VM deployment runbook (NEW 2026-06-24).
  - `docs/academic-article/findings-log.md` — canonical research/findings log (paper seed).
  - `docs/migration/ghidra-mcp-patches/` — local patches applied to pinned ghidra-mcp v5.6.0.
  - `docs/triage_api/` — Triage Cloud API reference; `docs/research/` — research reports.
  - `apps/web/AGENTS.md` and `apps/web/CLAUDE.md` — frontend-specific agent docs.
  - **`docs/operator-runbook.md` was DELETED (2026-06-01)** — do not reference it.
- Config reference: `.env.example` (root, heavily annotated incl. CAPE VM + RAG toggles) and
  `apps/api/.env.example`.

## Web UI (apps/web — see `mem:frontend_web_app`)
- Next.js 16 / React 19 / Tailwind 4 App Router. Auth pages + dashboard / jobs / audit / settings.
- The analysis detail view (`analysis/[id]/`) has 16 nav tabs (June 2026: TTPS merged into
  ATT&CK at `/capabilities`, Enterprise-only matrix): summary, identity, static, dynamic,
  network, persistence, attck/capabilities, attribution, signatures, defense, agents, pipeline,
  rules, timeline, stix, live. Playwright e2e exists.

## Design Principles
No hallucinated TTPs (ATT&CK validation + judge_postprocess), no sycophancy (cosine + Devil's
Advocate), graceful degradation everywhere, protocol-based extensibility, platform-aware filtering,
confidence integrity (degraded-mode cap).
