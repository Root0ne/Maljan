# Extractors, Enrichment, QA, Judge-Postprocess (report-grounding subsystems)

> Refreshed 2026-07-05. Cross-refs: `mem:reporting_layer`, `mem:isr_lifecycle`,
> `mem:api_infrastructure`.

## 1. `src/maljan/extractors/` — deterministic report-section builders
Each owns one `MalwareReport` section; graceful (never raises).
- `sample_identity.py` — hashes, file type, compile timestamp, signing. `_infer_platform(...)`
  now maps ONLY to windows/linux/unknown (`Platform` Literal narrowed 2026-06-02). **NEW:
  `unsupported_os_reason(sample_path)` (:214)** — 16-byte magic header check (authoritative:
  Mach-O/APK/IPA) + foreign-extension fallback (.apk/.dex/.ipa/.dmg/.pkg/.app/.scpt); used by
  `app.arun` to raise `UnsupportedSampleError` at entry. Renamed/obscure Win files NOT blocked.
- `pe_extractor.py` — PE/ELF static analysis; also feeds `build_sample_profile_text` for the
  family/case RAG query side.
- `dynamic_extractor.py` — process tree, registry mods, notable APIs, sandbox signatures.
- `network_extractor.py` — `build_network_iocs` + `merge_sandbox_cti_network`. **NEW (ff88307):
  DGA/IDN scoring** — `_dga_score(label)` = weighted blend of normalised Shannon entropy +
  common-bigram rarity + digit ratio; `_DGA_SCORE_THRESHOLD=0.55`, min label len 10; benign
  allowlist -> IDN/punycode homograph (`_idn_assessment`, mixed-script + `xn--` brand look-alike)
  -> C2 tokens -> DGA. Domain nodes get `dga_score`, `is_punycode`, `homograph_target`. **NEW:
  `build_dga_isr(network_iocs) -> AgentISR|None`** (:588) — judge-node Layer-0 ISR, agent_id
  `network_dga`, domain "network", T1568.002, rule_platforms=["any"]. Also ja3s_fingerprints.
- `persistence_extractor.py` — registry-run/services/scheduled tasks/WMI + Linux
  (systemd/cron/init.d/rc.local/LD_PRELOAD, + systemd_timer/xdg_autostart kinds). **NEW
  (09a3af3): COM hijacking (T1546.015)** — `_scan_com_hijack_calls` (:379) detects
  RegSetValueEx*/RegCreateKeyEx* under `CLSID\{guid}\` server subkeys (inprocserver32,
  localserver32, treatas, ...) -> `kind="com_hijacking"`; `_SIGNATURE_HINTS` maps
  com_hijack->T1546.015.
- `capability_matrix.py`, `attribution.py` — unchanged roles; attribution now also carries
  `function_hash_matches` + `attck_case_candidates` rows (see `mem:architecture_key_points` §5).

## 2. `src/maljan/analysis/lolbin_layer.py` — NEW Layer-0 LOLBin detection
`build_lolbin_isr(sandbox_report)` / `classify_lolbin(command_line)`: regsvr32->T1218.010,
rundll32->T1218.011, mshta->T1218.005. Fires only with a suspicious indicator (remote/scriptlet
URL, `/i:` squiblydoo, ordinal export `,#N`, user-writable payload path). `_CONFIDENCE=0.78`;
agent_id "lolbin", domain "dynamic", rule_platforms=["windows"]. Judge node injects it
(nodes.py:669); not config-gated; fail-safe.

## 3. Platform-aware filtering — flow unchanged (Wave 4), scope narrowed
`_infer_platform` -> `state["platform"]` (windows/linux/unknown) -> cascade
`_MITRE_PLATFORM_MAP` = windows/linux only -> Sigma/YARA platform filter ->
`run_summary.cascade.platform_filter_summary` -> fp_linter C1/C3/C6. Placeholder TTP denylist
(T0000/T9999/T1234). macOS/cloud Sigma rules removed (5820a7d, 7446446).

## 4. `src/maljan/enrichment/` — unchanged
VirusTotal (4 req/min sem+sleep, SSRF allowlist), AbuseIPDB, WHOIS (RDAP+GeoIP), orchestrator
(idempotent, fail-safe, cap 25/kind). ARQ `enrich_worker.py` or `POST /reports/{id}/enrich`.

## 5. `src/maljan/qa/fp_linter.py` — unchanged rules C1-C6
Runs in report_node after narrative+detection+STIX; warnings -> run_summary.

## 6. `src/maljan/agents/judge_postprocess.py` — defensive STIX passes
- J-01 UUID rewrite; J-02 evidence-corpus indicator dropout + file:name acceptance gate;
  REP-01 MITRE ref backfill; REP-02 cascade-orphan attack-pattern dropout.
- **NEW (2a65842): `enforce_bundle_integrity`** — applied after each drop step (and in
  stix_renderer): drops empty-pattern Indicators, dedups AttackPatterns by technique_id and
  Indicators by (pattern_type, pattern), rewrites relationship refs, drops dangling/duplicate
  relationships, trims dangling object_refs. `_technique_display_name(tid)` backfills names from
  the live ATT&CK index.
- `build_evidence_corpus(...)` unchanged.

## 7. `src/maljan/agents/_indicator_denylists.py` — unchanged
(MAX_FILE_NAME_INDICATORS=10, MAX_TOTAL_INDICATORS=15, etc.)

## 8. `src/maljan/memory/embeddings.py` — unchanged
384-dim fastembed BGE-small + BoW fallback; now shared by LTM stores AND the new
semantic/hybrid ATT&CK indexes + family/case/function indexes.
