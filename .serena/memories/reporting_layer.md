# Reporting Layer (`src/maljan/reporting/`)

> NEW subsystem (Faz 2-6), written 2026-05-30. A CTI-analyst-grade report layer that runs AFTER the
> judge node via `pipeline/nodes.py::make_report_node`. Cross-refs: `mem:extractors_enrichment_qa`,
> `mem:data_flow` (Phase 6), `mem:pipeline_deep_dive`.

## Big picture
The judge emits a **minimal STIX Bundle** (Malware + AttackPattern + Relationship). The reporting
layer builds a separate, comprehensive **`MalwareReport`** (Pydantic) from deterministic extractors +
an LLM narrative + auto-generated detection signatures, then renders markdown and an **extended**
STIX bundle. `MalwareReport` is NOT a STIX object; it embeds the extended bundle under
`stix_bundle_extended`.

## `reporting/models.py` — `MalwareReport` schema
Top-level fields: verdict, severity (`SeverityAssessment`), overall_confidence, `identity`
(`SampleIdentity` incl. `FileHashes` md5/sha1/sha256/sha512/imphash/ssdeep/tlsh + platform),
`static` (`StaticAnalysis`), `dynamic` (`DynamicBehavior` w/ recursive `ProcessNode` tree),
`network` (`NetworkIOCs`: domains/ips/urls/user_agents/ja3), `persistence`
(`list[PersistenceMechanism]`), `capability_matrix` (`list[CapabilityCell]`),
`ttp_mappings` (`list[TTPMapping]`), `attribution` (`FamilyAttribution` w/ `family_grounded` flag —
Wave 9 D11 guardrail), narrative fields (`executive_summary`, `capabilities_narrative`,
`defensive_recommendations` P0/P1/P2), `detection_signatures` (`list[DetectionRule]`
kind=yara/sigma/suricata/snort + body + compile_error), observability (`run_summary`,
`negotiation_summary`), IOC export (`stix_bundle_extended`, `misp_attributes`), `external_references`.

## `reporting/builder.py` — `MalwareReportBuilder`
- `__init__(file_hash, file_name, sample_path, sandbox_report, reports, isr_reports, stix_output,
  run_summary, discussion_history, final_decision, overall_confidence, cascade_summary,
  malware_category, sandbox_cti)`.
- `build_deterministic() -> MalwareReport`: calls the extractors — `build_sample_identity`,
  `build_static_analysis`, `build_dynamic_behavior`, `build_network_iocs` (+ `merge_sandbox_cti_network`
  W10-NET-01), `build_persistence_list`, `build_capability_matrix`, severity, `populate_similar_samples`.
- `apply_narrative(report, narrative_dict)` (static) — merges LLM prose.
- `attach_detection_signatures(report)` — calls `build_detection_rules(report)`.
- `apply_fallback_narrative(report)` — deterministic templated summary when LLM unavailable.

## `reporting/narrative_agent.py` — `NarrativeAgent` (LLM)
- `NarrativeOutput`: `executive_summary` (str), `capabilities_narrative` (list[str], 3-5 paras),
  `defensive_recommendations` (list[DefensiveRecommendation]).
- `async generate(report) -> NarrativeOutput | None`: two-path — `with_structured_output().ainvoke()`
  first, then plain `ainvoke()` + `safe_parse_json()` fallback (for llama.cpp). Returns None on total
  failure -> caller uses `apply_fallback_narrative`. Obtained via `container.get_narrative_agent()`.
  Senior-RE system prompt: cite ATT&CK IDs, no invented capabilities.

## `reporting/detection_signatures.py`
- `build_detection_rules(report) -> list[DetectionRule]` — 0-3 rules.
  - YARA: hash + imphash + interesting_strings (validated via `yara.compile()` if available).
  - Sigma: Windows event-log schema. **Gate**: refuses when `family_grounded=False` OR platform unknown.
  - YARA gate (Wave 9): mirrors the Sigma gate (avoid `Maljan_AutoGen_unknown` for ungrounded families).
  - Suricata: DNS/IP/HTTP from network IOCs (no platform/family gate).
  - Validation failures set `compile_error` but keep the body (operator can edit).

## `reporting/renderers/`
- `markdown.py` `MarkdownRenderer.render(report)` -> GitHub-flavoured markdown; each section wrapped
  in `_safe_section()` (Wave 9 — a malformed subtree can't 500 `/reports/{id}/markdown`).
- `stix_renderer.py` `ExtendedSTIXRenderer.render(report, base_bundle)` -> NEW Bundle augmenting the
  judge bundle with Identity (Maljan) / Indicator / ObservedData (process tree, capped) / Note
  (executive summary) / Report SDOs. Indicator acceptance reuses `_indicator_denylists`; Wave 9
  `MAX_TOTAL_INDICATORS=15` priority cap (hashes > network > file:name). Adds `x_maljan_cti` for Triage CTI.

## `ReportingConfig` (`core/config.py`)
`enabled=True`, `include_extended_stix=True`, `narrative_max_tokens=1500`,
`auto_generate_detection_rules=True`, `enrichment_async=True`.

## `report_node` flow (`pipeline/nodes.py::make_report_node`)
Feature-flag gate -> recompute cascade with `state["platform"]` -> derive `overall_confidence`
(cap 0.60 if `degraded_mode`, CONF-INFL-01) -> infer `malware_category` (CAT-PERSIST-01) ->
`build_deterministic()` -> narrative (LLM/fallback) -> `attach_detection_signatures` (if config) ->
markdown render -> extended STIX render -> `qa/fp_linter.lint_report()` (warnings into run_summary).
Outputs: `malware_report`, `malware_report_markdown`, `stix_bundle_extended`, updated `run_summary`.

## API surface
`GET /reports/{id}/full|markdown|iocs|signatures/{kind}`; `POST /reports/{id}/enrich`. See `mem:api_infrastructure`.
