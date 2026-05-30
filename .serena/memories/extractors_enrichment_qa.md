# Extractors, Enrichment, QA, Judge-Postprocess (report-grounding subsystems)

> NEW subsystems, written 2026-05-30. These feed and guard the reporting layer. Cross-refs:
> `mem:reporting_layer`, `mem:isr_lifecycle`, `mem:api_infrastructure`.

## 1. `src/maljan/extractors/` — deterministic report-section builders
Each owns one `MalwareReport` section; graceful (returns None/empty, never raises). Called by
`reporting/builder.build_deterministic()`.
- `sample_identity.py` — `build_sample_identity(...) -> SampleIdentity` (hashes incl. imphash/ssdeep/tlsh,
  file type, compile timestamp, signing). **`_infer_platform(...)` -> canonical platform** drives the
  whole Wave 4 platform pipeline. Strategy: magic bytes -> sandbox hints -> MIME (file_type wins so a
  misrouted sandbox can't poison inference). Also used by `MaljanApp` at bootstrap to seed `state["platform"]`.
- `pe_extractor.py` — `build_static_analysis(sample_path)`: PE (pefile) / ELF (pyelftools) / fallback;
  sections (entropy/RWX), imports/exports, packer + obfuscation hints, string IOCs (regex w/ FP filters).
- `dynamic_extractor.py` — `build_dynamic_behavior(sandbox_report)`: process tree (injection detect),
  registry mods, file ops, notable APIs, sandbox signatures.
- `network_extractor.py` — `build_network_iocs(sandbox_report)` + `merge_sandbox_cti_network(...)`
  (W10-NET-01: fold Triage SandboxCTI when CAPE-style network block empty).
- `persistence_extractor.py` — `build_persistence_list(sandbox_report)`: registry-run / services /
  scheduled tasks / WMI + Wave 9 Linux (systemd/cron/init.d/rc.local/LD_PRELOAD).
- `capability_matrix.py` — `build_capability_matrix(cascade_summary, isr_reports)` -> heatmap cells +
  TTPMappings (resolves names/tactics via ATT&CK index).
- `attribution.py` — `populate_similar_samples(report, store, top_k=5)`: Qdrant nearest-neighbour cases
  (semantic query from category/family/TTPs/signatures, not raw hashes). Idempotent.

## 2. Platform-aware filtering (Wave 4, 2026-05-28) — the flow
`sample_identity._infer_platform()` -> `MaljanApp` seeds `state["platform"]` -> judge & report nodes
read it -> `TTPCascadeEngine.compute(isr_reports, sample_platform=...)` drops platform-incompatible
techniques (resolution: source-rule `rule_platforms` -> MITRE catalog `_get_attck_catalog()` ->
`MOBILE_ENTERPRISE_OVERLAP`) -> Sigma/YARA layers filter rules by platform ->
`run_summary.cascade.platform_filter_summary` -> fp_linter C1/C3/C6 audit. Placeholder TTP denylist
(T0000/T0000.000/T9999/T1234). Origin: the 2026-05-23 zararli.apk run mapped Windows TTPs onto an APK.

## 3. `src/maljan/enrichment/` — post-pipeline threat-intel (out-of-band ARQ)
Runs AFTER the verdict via `apps/api/app/worker/enrich_worker.py` (or `POST /reports/{id}/enrich`).
Every provider is fail-safe (missing key/HTTP error/429/SSRF -> None + one warning); orchestrator idempotent.
- `orchestrator.py` — `async enrich_malware_report(report, vt_api_key, abuseipdb_api_key, ...,
  memory_store, similar_top_k)` -> mutates+returns report dict. Fills `network.domains[].reputation` +
  `network.ips[].{reputation,asn,geo}` (cap per kind, default 25) and runs attribution even with no IOCs.
- `virustotal_client.py` `VirusTotalClient` — domain/ip reputation; `asyncio.Semaphore(1)` + 16s sleep
  (4 req/min free tier); SSRF host allowlist `www.virustotal.com`.
- `abuseipdb_client.py` `AbuseIPDBClient` — `ip_check` (abuse confidence/country/isp); host `api.abuseipdb.com`.
- `whois_client.py` `WhoisClient` — `asn_lookup` (ipwhois RDAP -> ARIN bootstrap) + `geoip` (MaxMind .mmdb, optional).

## 4. `src/maljan/qa/fp_linter.py` — structural false-positive linter
`lint_report(report, sample_platform) -> list[FPWarning]` (rule C1-C6, severity warn/error). Called in
`report_node` after narrative + detection + STIX so it sees the final payload; warnings -> `run_summary`.
- C1: capability-matrix technique platform mismatch vs sample platform.
- C2: defensive recommendation cites a TTP absent from capability_matrix (narrative hallucination).
- C3: executive summary mentions a platform-incompatible concept (e.g. PowerShell/RDP on an APK) —
  the 2026-05-23 zararli.apk failure mode.
- C4: indicator overflow (`MAX_FILE_NAME_INDICATORS` / `MAX_TOTAL_INDICATORS`).
- C5: family attribution set but `family_grounded=False`.
- C6 (Wave 9): missing/zero `cascade.platform_filter_summary` when platform known.

## 5. `src/maljan/agents/judge_postprocess.py` — defensive STIX passes
Called inside `JudgeAgent.give_verdict()` BEFORE Bundle validation.
- `postprocess_judge_bundle(bundle_dict, evidence_corpus=None, valid_technique_ids=None)`:
  - J-01 — rewrite placeholder/non-UUID STIX IDs + all cross-refs to spec-compliant UUIDs.
  - J-02 — drop indicators whose pattern literal is absent from `evidence_corpus`; `[file:name`
    acceptance gate (reject compile artifacts / Android class refs; require real ext or OS-resource
    prefix or runtime path; cap `MAX_FILE_NAME_INDICATORS`); URL denylist.
  - REP-01 — backfill AttackPattern `external_references` with canonical MITRE URLs.
  - REP-02 (Wave 9) — drop AttackPatterns whose technique_id is not a cascade survivor
    (`valid_technique_ids`) + sweep dangling relationships.
- `build_evidence_corpus(interesting_strings, sandbox_report, extra) -> set[str]` (lower-cased tokens).

## 6. `src/maljan/agents/_indicator_denylists.py` — shared constants
`IOC_FILE_EXTENSIONS`, `IOC_OS_RESOURCE_PREFIXES`, `COMPILE_ARTIFACT_RE` (NDK/LLVM/clang paths),
`ANDROID_CLASS_REF_RE`, `URL_DENY_HOSTS` (dev/SDK hosts), `MAX_FILE_NAME_INDICATORS=10`,
`MAX_TOTAL_INDICATORS=15`. Imported by `judge_postprocess`, `reporting/renderers/stix_renderer`,
and `qa/fp_linter`. Origin: 2026-05-28 zararli.apk audit (~50 hallucinated NDK/class-ref indicators).

## 7. `src/maljan/memory/embeddings.py`
`encode(text)->list[float]` 384-dim (fastembed BAAI/bge-small-en-v1.5; BoW MD5-hash fallback,
L2-normalized), `cosine(a,b)`, `reset_cache()`. Shared, lazy, thread-safe. Used by `qdrant_store` +
`in_memory_store` (collection `maljan_cases_v2`).
