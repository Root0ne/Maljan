# Comprehensive Malware Reporting

This document describes the `MalwareReport` artifact produced by every Maljan
pipeline run after Phase 5. It is the single source of truth consumed by the
CLI (`--report` flag), the REST API (`GET /api/v1/reports/{id}/...`), and the
16-tab analysis UI.

## Why this exists

Earlier pipeline output was a short verdict + a minimal STIX 2.1 bundle and a
free-form negotiation summary. That was enough to answer "is this malware?"
but useless for the next analyst question: "what does it actually *do*, and
how do I detect it on my fleet?". The `MalwareReport` schema turns every
signal the pipeline already collects — sandbox process trees, PE imports,
sandbox signatures, MITRE technique mappings, narrative reasoning — into a
single Pydantic object that can be rendered as Markdown, STIX, MISP, or
streamed straight to React tabs without bespoke transformation.

## End-to-end pipeline

```
sample → ingestion → static + dynamic + network experts → negotiation
       → judge (verdict + minimal STIX) → report (THIS PHASE)
       → enrichment (VT / AbuseIPDB / WHOIS / Qdrant LTM)
       → DB + WebSocket fan-out → UI
```

The `report` node runs **after** the judge so it can layer narrative LLM
output on top of the deterministic extractor pass. The enrichment worker
runs **after** the report row is committed so verdict latency is unaffected.

## Schema overview

Source of truth:
[`src/maljan/reporting/models.py`](../src/maljan/reporting/models.py).

Top-level `MalwareReport` carries 22 fields grouped into four layers:

| Layer | Fields | Filled by |
| --- | --- | --- |
| Verdict & severity | `verdict`, `overall_confidence`, `malware_category`, `severity` | Judge + deterministic builder |
| Sample identity | `identity` (FileHashes, signing, magic bytes, compile timestamp) | `extractors/sample_identity.py` |
| Deterministic analyses | `static`, `dynamic`, `network`, `persistence`, `capability_matrix`, `ttp_mappings` | `extractors/*` |
| Attribution | `attribution` (family, actor, campaign, **similar_samples**) | Builder + Qdrant LTM (Phase 9) |
| LLM narrative | `executive_summary`, `capabilities_narrative`, `defensive_recommendations` | `reporting/narrative_agent.py` |
| Detection content | `detection_signatures` (YARA / Sigma / Suricata) | `reporting/detection_signatures.py` |
| Observability | `run_summary`, `negotiation_summary` | Pipeline state |
| IOC export | `stix_bundle_extended`, `misp_attributes` | `reporting/renderers/stix_renderer.py` |
| References | `references` (VT, MalwareBazaar, MITRE ATT&CK URLs) | Builder |

Sub-blocks (`static`, `dynamic`, `network`) are `None` when their source data
is unavailable — a sample-only run with no sandbox detonation still produces
a useful Identity + Static section. All collections default to empty
containers so the report is always serialisable.

`schema_version: "1.0"` — bumping it signals a breaking change. The top-level
model uses `extra="ignore"` so new fields can be added forward-compatibly;
inner blocks use `extra="forbid"` so extractor bugs surface immediately in
the test suite.

## Markdown render order

`MarkdownRenderer.render()`
([`src/maljan/reporting/renderers/markdown.py`](../src/maljan/reporting/renderers/markdown.py))
emits 16 sections in a fixed order. The CLI `--report` flag and the
`GET /reports/{id}/markdown` endpoint share the same renderer.

1. Header (verdict badge + sha256 + generated_at)
2. Sample Identification (hashes + signing + magic bytes)
3. Severity & Impact
4. Executive Summary
5. Capabilities Narrative
6. Static Analysis (sections, imports, strings)
7. Dynamic Behavior (process tree, registry mods, sandbox signatures)
8. Network IOCs (domains, IPs, URLs, JA3)
9. Persistence Mechanisms
10. MITRE ATT&CK Matrix (tactic × technique grid)
11. Capability Matrix (TTPMapping with evidence quotes)
12. Family Attribution (family + actor + campaign + similar samples)
13. Detection Signatures (YARA / Sigma / Suricata code blocks)
14. Defensive Recommendations (P0 → P1 → P2)
15. References
16. Run Summary (embedded `RunSummary.to_markdown()`)

## CLI usage

```
uv run maljan analyze <sha256> -s data/samples/zararli.elf \
    --provider openai -i 3 --name report-test --report report.md
```

When `--report` is set, Maljan writes the rendered Markdown produced by
the `report` node (already in pipeline state under
`malware_report_markdown`). If that key is absent (e.g. legacy run with
`MALJAN_REPORTING__ENABLED=false`), the CLI falls back to the legacy
`RunSummary.to_markdown()` output.

`MALJAN_REPORTING__ENABLED=false` flips the pipeline back to
`judge → END`, so the report node is skipped entirely. Defaults to
`true`.

## REST endpoints (Phase 5)

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/reports/{report_id}/full` | Full `MalwareReport` JSON |
| `GET /api/v1/reports/{report_id}/markdown` | `text/markdown` rendering |
| `GET /api/v1/reports/{report_id}/iocs?kind=` | Flattened IOC list |
| `GET /api/v1/reports/{report_id}/signatures/{kind}` | `text/plain` YARA/Sigma/Suricata |
| `POST /api/v1/reports/{report_id}/enrich` | Trigger threat-intel enrichment job (Phase 6) |

The detail endpoint (`GET /api/v1/reports/{id}`) carries the same payload
on the new `malware_report` field. Legacy rows where `malware_report=NULL`
return `null` — the frontend falls back to `LegacySummary` rendering in
[`apps/web/src/app/(app)/analysis/[id]/page.tsx`](../apps/web/src/app/(app)/analysis/[id]/page.tsx).

## WebSocket events

Live updates are published on Redis channel `analysis:{job_id}` and
forwarded by the `/ws/analysis/{job_id}` endpoint:

- `pipeline_started`, `agent_progress`, `phase_change`, `completed` — from
  the analysis worker.
- `enrichment_complete` — emitted by the post-hoc enrichment worker
  ([`apps/api/app/worker/enrich_worker.py`](../apps/api/app/worker/enrich_worker.py))
  once VT/AbuseIPDB/Qdrant lookups finish. Payload includes
  `domains_enriched`, `ips_enriched`, `similar_samples`. The frontend's
  layout listens for this event and one-shot refetches the report so
  the Network and Attribution tabs reflect the new payload without
  waiting for the polling cycle.

## Threat intel enrichment (Phase 6 + 9)

The enrichment worker fills three categories of fields **after** the
report row is committed, so the verdict response stays fast:

- `network.domains[*].reputation` and `network.ips[*].reputation` —
  VirusTotal v3 + AbuseIPDB v2.
- `network.ips[*].asn` / `network.ips[*].geo` — WHOIS RDAP +
  optional MaxMind GeoIP.
- `attribution.similar_samples[]` — top-k nearest-neighbour cases from
  the Qdrant LTM. Query is built from category, family, top-10 TTPs,
  and top-5 sandbox signatures. The sample's own sha256 is filtered
  out of results.

Every provider client is **fail-safe by design**: missing API keys,
rate-limit responses, SSRF attempts and unreachable Qdrant instances all
degrade to `None` with a single warning log. The worker never raises.

API keys are optional and read from `.env`:

```
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
MEMORY__QDRANT_URL=http://localhost:6333
MEMORY__QDRANT_COLLECTION=maljan_cases_v2
```

Trigger the enrichment manually with:

```
curl -X POST -H "Authorization: Bearer $TOKEN" \
    http://localhost:8000/api/v1/reports/{report_id}/enrich
```

The endpoint is idempotent — duplicate calls are coalesced via the ARQ
`_job_id="enrich:{report_id}"` unique key.

## Frontend tabs (Phase 7 + 8 + 9)

The analysis page at `/analysis/[job_id]/` exposes 16 tabs in four
visual groups (see
[`apps/web/src/app/(app)/analysis/[id]/layout.tsx`](../apps/web/src/app/(app)/analysis/[id]/layout.tsx)):

- **Overview**: Summary, Identity
- **Analysis**: Static, Dynamic, Network, Persistence
- **Intel**: ATT&CK heatmap, Attribution, Signatures, Defense
- **Advanced**: Agents, Pipeline, Rules, TTPs, Timeline, STIX

The Summary tab carries `Download` buttons that pull the Markdown,
extended STIX bundle, and MISP attribute list directly from the report
payload.

## Extending the report

Two extension points cover most needs:

1. **New deterministic field** — add the field to
   [`src/maljan/reporting/models.py`](../src/maljan/reporting/models.py),
   write or extend an extractor in
   [`src/maljan/extractors/`](../src/maljan/extractors/), wire it in
   [`src/maljan/reporting/builder.py`](../src/maljan/reporting/builder.py:82),
   add a section to
   [`src/maljan/reporting/renderers/markdown.py`](../src/maljan/reporting/renderers/markdown.py),
   and surface it in a new frontend tab (mirror the existing tab pattern
   under `apps/web/src/app/(app)/analysis/[id]/`).
2. **New post-hoc enrichment** — add a provider client under
   [`src/maljan/enrichment/`](../src/maljan/enrichment/) following the
   `VirusTotalClient` template (host whitelist, fail-safe `None` returns),
   then thread it through
   [`src/maljan/enrichment/orchestrator.py`](../src/maljan/enrichment/orchestrator.py).
   The ARQ worker picks up the new field automatically.

If you change the public shape, bump `schema_version` and document the
break — every consumer (DB JSONB column, REST API, React types in
[`apps/web/src/types/malware-report.ts`](../apps/web/src/types/malware-report.ts))
relies on it.

## Test fixtures

Ground-truth fixtures live under
[`tests/evaluation/fixtures/`](../tests/evaluation/fixtures/) — five JSON
files (dropper, infostealer, ransomware, RAT, worm) carrying expected
technique IDs and STIX object types. Use
`uv run maljan benchmark --fixtures-dir tests/evaluation/fixtures/` to
run the perfect-precision baseline against all of them.

Unit-level golden tests are at
[`tests/unit/reporting/`](../tests/unit/reporting/) and
[`tests/integration/test_report_pipeline.py`](../tests/integration/test_report_pipeline.py).
The integration test exercises the full pipeline in mock mode and asserts
that every section of the rendered Markdown is present.
