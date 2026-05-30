# Maljan Operator Runbook

Curated environment + runtime notes for operating the Maljan multi-agent
malware analysis pipeline locally. Audit-traced from production live runs
(2026-05-28 zararli.apk through 2026-05-30 zararli.apk + Mirai ELF).

This document complements the in-repo `CLAUDE.md` and `AGENTS.md` files
— those describe coding conventions; this one describes what the
operator must do on the host machine to make the stack work reliably.

---

## 1. Sandbox / Defender Exclusions (W10-ENV-04)

### Why this matters

Maljan analyses real malware samples. On Windows hosts running Microsoft
Defender with default real-time protection, the analyser pipeline
repeatedly opens malware binaries for reading (worker MinIO download,
TriageClient upload, Ghidra container bind-mount). Defender's signature
database flags many of these binaries as known threats and silently
intercepts the file open with `[Errno 22] Invalid argument` — surfacing
as `Storage service unavailable` (HTTP 503) or unexplained worker
failures.

The 2026-05-29 Mirai ELF smoke test exposed this:
- The Linux ELF sample
  `7d80f4508ee1cbabdc4b5a813d5cef0a00731b3a064bf1afb0cb4a24522661be.elf`
  is a known-bad signature in Defender's malware corpus.
- Wave 9 ERGO-06 changed the upload tempdir to `data/uploads/.tmp` on
  the (incorrect) assumption that `%LOCALAPPDATA%\Temp` was the
  quarantine zone. Defender RTP is signature-driven, not path-driven,
  so the change made no difference; the ELF was blocked at every
  candidate path.
- The APK sample `zararli.apk` did NOT trigger the signature scan and
  flowed through cleanly — so the smoke test on APK can succeed
  without the exclusions; ELF / known-PE samples need them.

### How to configure

Open an elevated PowerShell prompt and add the project tree to
Defender's exclusion list:

```powershell
Add-MpPreference -ExclusionPath 'D:\Projects\Maljan\data'
Add-MpPreference -ExclusionPath 'D:\Projects\Maljan\models'
Add-MpPreference -ExclusionPath 'D:\Projects\Maljan\external'
```

Adjust the prefix if the repo lives elsewhere. The three directories
cover:

| Path | What lives there |
|---|---|
| `data\` | sample uploads (`data\samples\`, `data\uploads\.tmp\`), Triage / Ghidra working copies |
| `models\` | GGUF weights (Qwen3.6-35B-A3B-IQ3_K_R4.gguf and similar) |
| `external\` | the local `ik_llama.cpp` build output (the `llama-server.exe` binary itself) |

Verify the exclusions were applied (elevated PowerShell):

```powershell
(Get-MpPreference).ExclusionPath
```

A non-elevated session reports `N/A: Must be an administrator to view exclusions`.

### What if you can't add exclusions

If the operator workstation is corporate-managed and the exclusion list
is locked, the alternatives are:

- Restrict the analyst pool to non-Defender-flagged samples (most APK
  and PDF research samples are safe; ELF Mirai-class and PE LockBit-class
  samples are not).
- Run the worker and llama-server on a Linux host (no Defender) and
  point the API container at it via `LLM__OPENAI__BASE_URL`.
- Disable real-time protection only for the duration of a run via
  `Set-MpPreference -DisableRealtimeMonitoring $true` and re-enable
  immediately after. This requires elevation and should be the last
  resort — the host has live malware on disk while RTP is off.

---

## 2. llama-server Context Window (W10-LLM-05)

### Why this matters

The static analyst runs a multi-round ReAct loop driving the Ghidra
MCP server. Each round embeds the active tool schemas (currently
12 tools from `kept 12/165 tools via static-analyst allowlist`) plus
the accumulated conversation history. By round 3-4 of a clean run the
prompt comfortably crosses 16k tokens.

At `-c 16384` ik_llama.cpp's llama-server has no headroom for context
shift (the moving-window strategy that drops the oldest tokens to
keep the conversation fitting). It returns HTTP 500
`{'error': {'code': 500, 'message': 'context shift is disabled'}}` and
the static analyst fails. The 2026-05-30 APK + ELF smoke runs both
hit this at the static analyst stage.

### The current setting

`run_llama.ps1` now ships with `-c 32768` (32 k tokens), bumped from
16 k by Wave 10 W10-LLM-05. With `-ctk q8_0` the KV cache grows by
~64 MiB beyond the 16 k baseline — well within the RTX 5060's 8 GiB
budget alongside the IQ3_K_R4 weights at `--n-cpu-moe 36` MoE offload
(roughly 7 GiB resident on GPU).

### Tuning for other cards

| GPU | Recommended -c |
|---|---|
| RTX 4060 8 GB / 5060 8 GB | 32768 |
| RTX 4070 12 GB / 4080 16 GB | 65536 or 131072 |
| RTX 3060 8 GB (compute 86) | 16384 — bump `--n-cpu-moe` first |
| < 8 GB VRAM | keep 16384 and reduce `react.max_iterations` in `Settings.negotiation` to 3 |

Smoke-test after any change by submitting `zararli.apk` and watching
the static analyst's first `chat/completions` response for HTTP 500.
A successful round emits a `static ReAct loop: elapsed=Ns, tool_calls=K, messages=L`
INFO line in the worker log.

---

## 3. Stack Bring-up Order

Standard cold-start sequence (from a clean reboot):

```powershell
# 1. Docker stack (postgres, redis, minio, qdrant, ghidra-mcp)
docker compose --env-file .env -f docker/docker-compose.yml up -d

# 2. llama-server (background; takes 1-3 min to load the 14 GB GGUF)
./run_llama.ps1

# 3. ARQ worker (idles until a job is queued)
./run_worker.ps1

# 4. FastAPI backend
$env:PYTHONPATH = "D:\Projects\Maljan\apps\api;D:\Projects\Maljan\src"
& "D:\Projects\Maljan\.venv\Scripts\uvicorn.exe" app.main:app `
  --host 0.0.0.0 --port 8000

# 5. Next.js dev server (in apps/web)
cd D:\Projects\Maljan\apps\web; npm run dev
```

Health probes:

```powershell
curl http://127.0.0.1:8000/health     # 200 = API up
curl http://127.0.0.1:8080/health     # 200 = llama-server slot idle
curl http://127.0.0.1:3000            # 307 = web auth redirect (auth disabled in dev)
```

The web UI exposes its full surface at `http://localhost:3000/dashboard`
once auth is bypassed via `AUTH_DISABLED=true` in `.env`.

---

## 4. Known Operational Gotchas

Closed in 2026-05-30 Wave 10:

- **`apps/api/.venv` pydantic_core import fails** (W10-VENV-06) — root
  cause was a uv-cache hardlink corruption that left ``pydantic_core``
  installed without its compiled wheel. Repair with::

    cd apps/api
    $env:VIRTUAL_ENV = (Resolve-Path .\.venv).Path
    uv pip install --reinstall pydantic-core

  After the reinstall the version moves to ``2.47.0`` and ``import
  pydantic`` succeeds. The repo's root ``.venv`` was unaffected.

- **ESLint v9 config migration** (W10-LINT-07) — ``apps/web/eslint.config.mjs``
  now carries the flat-config recipe sourced from
  ``node_modules/next/dist/docs/01-app/03-api-reference/05-config/03-eslint.md``.
  ``apps/web/node_modules/.bin/eslint.cmd .`` returns exit 0 with 17
  warnings, 0 errors after the W10-LINT-DEBT-01/02 sweeps.

- **Mobile ATT&CK tactics render as "Unknown TA0000"** (W10-TTP-02) —
  ``apps/web/src/lib/mitre-mobile.ts`` ships a curated TID → tactic
  lookup for ~60 Mobile ATT&CK techniques. The TTPS tab now exposes
  a Mobile/Enterprise/ICS matrix selector and auto-promotes whichever
  matrix has techniques.

Still tracked as backlog:

- **Defender real-time protection blocks malware reads** (W10-ENV-04) —
  the recipe in section 1 above must be applied per operator host.
  The classifier blocked the automated apply in the 2026-05-30
  Wave 10 session ("Adding Windows Defender exclusion paths weakens
  endpoint security controls; user's generic 'continue' does not
  explicitly authorize modifying host AV configuration"). Operator
  must run the elevated PowerShell commands manually.

---

## 5. Trace Log: Wave 9 → Wave 10 Findings

Annotated breadcrumbs so future readers can locate the audit
artifacts that drove each change:

| Wave | Theme | Audit artifact |
|---|---|---|
| 4 D11 | family ungrounded guardrail | 2026-05-23 zararli.apk report (legacy id `69491221`) |
| 4 platform-aware cascade | 6 platform FPs | 2026-05-23 zararli.apk audit |
| 6 GHIDRA-DELIVERY-01 | container can't see sample | 2026-05-28 live trace |
| 7 THROUGHPUT-01 | analysts queueing on single slot | 2026-05-28 ProductionA test |
| 8 ORPHAN-JOBS-01 | 4 phantom running rows | 2026-05-28 dashboard audit |
| 9 PERSIST-01 | empty Linux ELF persistence | 2026-05-29 Mirai audit `f072cd22` |
| 9 STIX-CAP-02 | 19 indicator overflow | same Mirai audit |
| 9 ERGO-06 | upload quarantine theory (proven incorrect) | same Mirai audit |
| 9 HOTFIX-08 | upload_temp_dir relative-path regression | 2026-05-30 job f4a1fee9 |
| 9 HOTFIX-09 | fp_warnings missing in DTO | 2026-05-30 UI walk |
| 10 NET-01 | SandboxCTI network IOCs not in MalwareReport.network | 2026-05-30 zararli.apk UI walk (report 282abfe8) |
| 10 OBS-03 | platform_filter_summary not surfaced | same UI walk |
| 10 ENV-04 | this runbook | same UI walk |
| 10 LLM-05 | -c 16384 context shift | 2026-05-30 APK + ELF static analyst failures |
