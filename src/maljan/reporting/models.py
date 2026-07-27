"""Pydantic models for the comprehensive malware analysis report.

``MalwareReport`` is the single source of truth: every CLI/API/UI consumer
reads from this shape. Extractors fill the deterministic fields, the
``NarrativeAgent`` fills the LLM-written narrative fields, and the renderers
(markdown / STIX / MISP / JSON) consume the whole structure.

Design notes:

- All collections default to empty containers (``Field(default_factory=...)``)
  so the report is always serialisable even when sandbox/static data is
  partial. Optional structural blocks (``static``, ``dynamic``, ``network``)
  are ``None`` when the matching data source was unavailable.
- ``ProcessNode`` is recursive — ``ProcessNode.model_rebuild()`` is called at
  module import time so Pydantic can resolve the forward reference.
- ``schema_version`` is a string literal — bumping it signals a breaking
  change to consumers (DB migration may be required).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from maljan.schemas.stix_models import get_utcnow

# ---------------------------------------------------------------------------
# Shared base configuration
# ---------------------------------------------------------------------------

# We deliberately allow forward-compatible extra fields on top-level reports
# (so downstream consumers do not crash when we add new sections), but inner
# building blocks use ``extra="forbid"`` to catch extractor bugs early.
_STRICT_CONFIG = ConfigDict(extra="forbid")
_PERMISSIVE_CONFIG = ConfigDict(extra="ignore")


# ---------------------------------------------------------------------------
# Severity & Identification
# ---------------------------------------------------------------------------


class SeverityAssessment(BaseModel):
    """CVSS-style summary used for the report header and dashboard sorting."""

    model_config = _STRICT_CONFIG

    overall_score: Annotated[float, Field(ge=0.0, le=10.0)] = 0.0
    rating: Literal["Critical", "High", "Medium", "Low", "Informational"] = "Informational"
    business_impact: str = ""
    affected_platforms: list[str] = Field(default_factory=list)
    likely_targets: list[str] = Field(default_factory=list)


class FileHashes(BaseModel):
    """Cryptographic and fuzzy hashes for the sample under analysis."""

    model_config = _STRICT_CONFIG

    md5: str | None = None
    sha1: str | None = None
    sha256: str
    sha512: str | None = None
    imphash: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None


class SignatureInfo(BaseModel):
    """Digital-signing metadata extracted from PE / ELF / etc."""

    model_config = _STRICT_CONFIG

    is_signed: bool = False
    signer_subject: str | None = None
    signer_issuer: str | None = None
    signature_valid: bool | None = None


# Canonical platform taxonomy. Used by SampleIdentity, the rule layers
# (Sigma/YARA), the TTP cascade, and the FP linter. "crossplatform"
# is for samples that don't bind to one OS (e.g. JAR). "unknown" is
# the conservative default when magic bytes don't identify the format
# and the sandbox couldn't disambiguate either.
# OS-support scope (2026-06-02): the pipeline supports Windows and Linux only —
# the CAPEv2 sandbox produces dynamic reports for those two guests, and the
# ATT&CK mapping / static identity layers were narrowed to match. Foreign
# (non-Win/Linux) samples resolve to "unknown" — there is no broader taxonomy.
Platform = Literal[
    "windows",
    "linux",
    "unknown",
]


class SampleIdentity(BaseModel):
    """Everything needed to uniquely identify the sample on disk and in CTI."""

    model_config = _STRICT_CONFIG

    hashes: FileHashes
    file_name: str | None = None
    file_size_bytes: int = 0
    file_type: str = "unknown"
    # Wave 4 (2026-05-28): the canonical platform inferred from
    # file_type with sandbox fallback. Drives Sigma/YARA rule filtering
    # and TTP cascade platform-aware drop decisions.
    platform: Platform = "unknown"
    mime_type: str | None = None
    magic_bytes: str = ""  # hex string of first 16 bytes
    compile_timestamp: datetime | None = None
    language_or_compiler: str | None = None
    signing: SignatureInfo = Field(default_factory=SignatureInfo)


# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------


class PESection(BaseModel):
    """One PE section row (``.text``, ``.data``, ``.rsrc``, ...)."""

    model_config = _STRICT_CONFIG

    name: str
    virtual_address: str  # hex string, e.g. "0x1000"
    virtual_size: int = 0
    raw_size: int = 0
    # File offset of this section's raw data. Needed to locate the overlay —
    # everything past the last section's raw end, which is where a dropper's
    # appended payload lives and which no section header describes.
    raw_offset: int = 0
    entropy: float = 0.0
    characteristics: str = ""
    is_suspicious: bool = False  # high entropy or RWX flags


class ImportRow(BaseModel):
    """Single DLL→function import row."""

    model_config = _STRICT_CONFIG

    dll: str
    function: str
    is_suspicious: bool = False
    category: str | None = None  # "process_injection", "anti_debug", "network", ...


class StringIOC(BaseModel):
    """A static string that looks like an indicator of compromise."""

    model_config = _STRICT_CONFIG

    value: str
    kind: Literal[
        "url",
        "ip",
        "registry",
        "path",
        "mutex",
        "domain",
        "email",
        "command",
        # Leaked credentials (API keys, tokens, private-key headers) and
        # cryptocurrency addresses. Typed rather than dumped into "other"
        # because build_consolidated_iocs and the STIX renderer both filter by
        # kind, so an untyped indicator is silently absent from the IOC table
        # and the exported bundle — the two places a responder would look.
        "secret",
        "crypto_wallet",
        "other",
    ]
    notes: str | None = None


class StaticAnalysis(BaseModel):
    """Findings from binary parsing / disassembly (no execution)."""

    model_config = _STRICT_CONFIG

    sections: list[PESection] = Field(default_factory=list)
    imports: list[ImportRow] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    interesting_strings: list[StringIOC] = Field(default_factory=list)
    embedded_resources: list[dict[str, Any]] = Field(default_factory=list)
    packer_hint: str | None = None
    # Ranked packer/protector identifications: {name, kind, confidence, method,
    # evidence}. `packer_hint` is the display string derived from the top row.
    # The list exists because a *confidence* is what downstream needs — the
    # T1027 over-claim cap keys on "is this really packed", and a bare
    # non-None string cannot answer that.
    packer_matches: list[dict[str, Any]] = Field(default_factory=list)
    obfuscation_indicators: list[str] = Field(default_factory=list)
    # {behaviour_category: count} over the resolved import table. Cheap to carry
    # and it saves every consumer — prompt, report, family RAG — from
    # recomputing the same histogram from ``imports``.
    api_capabilities: dict[str, int] = Field(default_factory=dict)
    # The audit trail behind the import-capability Layer-0 claims: one row per
    # technique with the exact imports that evidenced it. Without this a reader
    # sees a technique in the report and has no way to check the reasoning.
    api_technique_hits: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Dynamic behaviour
# ---------------------------------------------------------------------------


class ProcessNode(BaseModel):
    """A node in the process tree, recursively containing children."""

    model_config = _STRICT_CONFIG

    pid: int
    ppid: int = 0
    name: str = ""
    command_line: str = ""
    children: list[ProcessNode] = Field(default_factory=list)
    injected_into: list[int] = Field(default_factory=list)


class RegistryMod(BaseModel):
    """One registry create/modify/delete observation from the sandbox."""

    model_config = _STRICT_CONFIG

    hive: Literal["HKLM", "HKCU", "HKCR", "HKU", "HKCC", "UNKNOWN"] = "UNKNOWN"
    key: str
    value_name: str | None = None
    operation: Literal["create", "modify", "delete", "query"] = "modify"
    new_value: str | None = None


class SandboxSignature(BaseModel):
    """One CAPEv2 / Cuckoo signature hit with all its evidence marks."""

    model_config = _STRICT_CONFIG

    name: str
    description: str = ""
    severity: int = 0
    technique_ids: list[str] = Field(default_factory=list)
    marks: list[str] = Field(default_factory=list)


class DynamicBehavior(BaseModel):
    """Aggregated sandbox behaviour: processes, registry, files, API stats, sigs."""

    model_config = _STRICT_CONFIG

    process_tree: list[ProcessNode] = Field(default_factory=list)
    registry_mods: list[RegistryMod] = Field(default_factory=list)
    file_operations: list[dict[str, Any]] = Field(default_factory=list)
    notable_apis: list[dict[str, Any]] = Field(default_factory=list)
    sandbox_signatures: list[SandboxSignature] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Network IOCs
# ---------------------------------------------------------------------------


class NetworkDomain(BaseModel):
    """Observed FQDN (DNS query / HTTP host / SNI)."""

    model_config = _STRICT_CONFIG

    fqdn: str
    queried_pids: list[int] = Field(default_factory=list)
    resolved_ips: list[str] = Field(default_factory=list)
    is_suspicious: bool = False
    reason: str | None = None
    # DGA likelihood in [0,1] (Shannon entropy + bigram rarity + supporting
    # signals); None when the label was too short to score.
    dga_score: float | None = None
    # IDN/punycode homograph signals.
    is_punycode: bool = False
    homograph_target: str | None = None
    # Filled asynchronously by the threat-intel enrichment worker.
    reputation: dict[str, Any] | None = None


class NetworkIP(BaseModel):
    """Observed IPv4 / IPv6 endpoint."""

    model_config = _STRICT_CONFIG

    address: str
    port: int | None = None
    transport: Literal["tcp", "udp", "icmp", "other"] | None = None
    asn: str | None = None
    geo: str | None = None
    is_suspicious: bool = False
    reputation: dict[str, Any] | None = None


class NetworkURL(BaseModel):
    """Observed HTTP request URL."""

    model_config = _STRICT_CONFIG

    url: str
    method: str = "GET"
    status: int | None = None
    user_agent: str | None = None


class NetworkIOCs(BaseModel):
    """Container for every typed network indicator from the sandbox."""

    model_config = _STRICT_CONFIG

    domains: list[NetworkDomain] = Field(default_factory=list)
    ips: list[NetworkIP] = Field(default_factory=list)
    urls: list[NetworkURL] = Field(default_factory=list)
    user_agents: list[str] = Field(default_factory=list)
    ja3_fingerprints: list[str] = Field(default_factory=list)
    ja3s_fingerprints: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class PersistenceMechanism(BaseModel):
    """One detected persistence mechanism, mapped to MITRE where possible."""

    model_config = _STRICT_CONFIG

    # Wave 9 (2026-05-29): Linux ELF persistence kinds added so the
    # 2026-05-29 Mirai ELF audit's PERSISTENCE tab renders real signal
    # instead of empty. Windows kinds remain canonical for PE.
    kind: Literal[
        # ── Windows (PE) ─────────────────────────────────────
        "registry_run",
        "scheduled_task",
        "service",
        "wmi_subscription",
        "com_hijacking",
        "startup_folder",
        "dll_search_hijacking",
        "driver",
        "image_hijack",
        "appinit_dll",
        "lsa_provider",
        "winlogon_helper",
        # ── Linux (ELF) — Wave 9 ─────────────────────────────
        "systemd_service",
        "systemd_timer",
        "cron_job",
        "init_d",
        "rc_local",
        "ld_preload",
        "xdg_autostart",
        # ── Fallback ─────────────────────────────────────────
        "other",
    ]
    target: str  # registry path / file path / service name
    payload: str = ""  # command line / dll path / binary
    technique_id: str | None = None
    evidence_ref: str = ""


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------


class CapabilityCell(BaseModel):
    """One cell in the tactic×technique heatmap."""

    model_config = _STRICT_CONFIG

    tactic: str  # ATT&CK tactic ID, e.g. "TA0002"
    tactic_name: str
    technique_id: str  # e.g. "T1055"
    technique_name: str
    evidence: list[str] = Field(default_factory=list)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    contributing_layers: list[str] = Field(default_factory=list)


class TTPMapping(BaseModel):
    """Detailed technique→evidence record, richer than ``CapabilityCell``."""

    model_config = _STRICT_CONFIG

    technique_id: str
    technique_name: str
    tactic: str = ""
    tactic_name: str = ""
    evidence_quotes: list[str] = Field(default_factory=list)
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    contributing_layers: list[str] = Field(default_factory=list)
    is_corroborated: bool = False


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


class FamilyAttribution(BaseModel):
    """Best-guess malware family / actor / campaign attribution."""

    model_config = _STRICT_CONFIG

    family: str | None = None
    family_confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    # D11 grounding flag — True when the family was named by at least one
    # supporting source (sandbox CTI ``family[]``, sandbox signature, or
    # an ISR claim). False means the value came from the LLM/heuristic
    # path with no evidence in the deterministic layers; the UI should
    # render it with a "low confidence" badge. Defaults to True so legacy
    # rows persisted before the guardrail (where every populated family
    # was implicitly grounded) keep their meaning.
    family_grounded: bool = True
    actor: str | None = None
    campaign: str | None = None
    # Filled by ``attribution.py`` from the Qdrant LTM nearest neighbours.
    similar_samples: list[dict[str, Any]] = Field(default_factory=list)
    # Exact normalized-opcode-hash matches against previously analysed samples
    # (deterministic code-reuse links). Each row: family, confidence,
    # shared_functions, sample_ids, example_functions, match_method, source.
    # Populated by the report builder from the judge node's function-hash pass.
    function_hash_matches: list[dict[str, Any]] = Field(default_factory=list)
    # Offensive-tool / commodity-RAT byte markers found in the sample or in a
    # carved payload. Each row: family, tool, kind, confidence, markers.
    # Sibling of function_hash_matches, and the only family source that works
    # without a sandbox — cti.family[] is otherwise the sole producer.
    tool_artifact_matches: list[dict[str, Any]] = Field(default_factory=list)
    # Family-feature RAG candidates — families retrieved by static-feature
    # similarity to a reference fingerprint KB, surfaced as evidence the LLM
    # weighed (sibling of function_hash_matches). Each row: family, similarity,
    # malware_category, sample_count, match_method, source. Populated by the report
    # node from the judge node's RAG pass (empty unless the RAG is enabled and a
    # fingerprint catalog is present).
    family_rag_candidates: list[dict[str, Any]] = Field(default_factory=list)
    # ATT&CK case-prior RAG candidates (§4 U2) — ATT&CK techniques that recur in
    # behaviourally-similar prior cases mined from our own long-term memory, surfaced
    # as advisory evidence the analyst weighed (sibling of family_rag_candidates). Each
    # row: technique_id, support, similarity, match_method, source. Populated by the
    # report node from the judge node's ATT&CK-case RAG pass (empty unless the RAG is
    # enabled and a case corpus is present).
    attck_case_candidates: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection rules + defence
# ---------------------------------------------------------------------------


class DetectionRule(BaseModel):
    """Auto-generated detection content with the body kept as plain text."""

    model_config = _STRICT_CONFIG

    kind: Literal["yara", "sigma", "suricata", "snort"]
    name: str
    body: str
    auto_generated: bool = True
    source_evidence: list[str] = Field(default_factory=list)
    compile_error: str | None = None  # only set when template validation fails


class DefensiveRecommendation(BaseModel):
    """One actionable blue-team recommendation."""

    model_config = _STRICT_CONFIG

    category: Literal[
        "firewall",
        "edr_hunting",
        "registry_hardening",
        "gpo",
        "patching",
        "user_awareness",
        "other",
    ]
    action: str
    rationale: str
    priority: Literal["P0", "P1", "P2"]
    # 2026-07 round 2: link each recommendation to the ATT&CK technique it
    # defends against, and carry concrete detection guidance (specific API /
    # registry key / telemetry source / sigma-yara pointer) rather than prose.
    technique_id: str | None = None
    detection: str | None = None


class ExternalReference(BaseModel):
    """Outbound link in the report references section."""

    model_config = _STRICT_CONFIG

    source: str  # "VirusTotal", "MalwareBazaar", "MITRE ATT&CK", ...
    url: str
    note: str | None = None


# ---------------------------------------------------------------------------
# Professional-report front-matter & technical spine (report-reshaping Phase 2)
# ---------------------------------------------------------------------------
#
# Additive, all-optional containers modelled on the reference spec at
# docs/report-reference/malware-analysis-report-reference.md. Deterministic
# extractors (Phase 3) fill the front-matter / IOC / fingerprint fields; the
# section-wise Composer (Phase 4) fills the prose subsections, each grounded in
# captured tool evidence. Every field defaults empty so a report never regresses
# when a section has no evidence — the renderer states absence explicitly.

TLPLevel = Literal["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]


class VersionHistoryEntry(BaseModel):
    """One row of the report's revision-history table (reference §2)."""

    model_config = _STRICT_CONFIG

    version: str
    date: str
    authors: str
    description: str


class ReportFrontMatter(BaseModel):
    """Cover / front-matter identity block (reference §1)."""

    model_config = _STRICT_CONFIG

    publisher: str = "Maljan"
    product_type: str = "Malware Analysis Report"
    malware_name: str | None = None  # headline name (family or sample-derived)
    codename: str | None = None
    subtitle: str | None = None  # one-line targeting descriptor
    version: str = "1.0"
    report_date: str | None = None
    report_number: str | None = None
    authors: str | None = None
    team: str | None = None
    tlp: TLPLevel = "CLEAR"
    copyright: str | None = None
    license: str | None = None


class CliFlag(BaseModel):
    """A single command-line flag/argument the sample accepts (reference §8.2)."""

    model_config = _STRICT_CONFIG

    flag: str
    description: str
    evidence_ref: str | None = None


class ServiceProcessKill(BaseModel):
    """Service/process termination behaviour (reference IV.1)."""

    model_config = _STRICT_CONFIG

    kill_list: list[str] = Field(default_factory=list)
    white_list: list[str] = Field(default_factory=list)
    mechanism: str | None = None  # e.g. "Toolhelp32 + ControlService", "net stop / taskkill"


class EncryptionScheme(BaseModel):
    """Reverse-engineered crypto scheme (reference I.6 / IV.1)."""

    model_config = _STRICT_CONFIG

    cipher: str | None = None  # e.g. "AES-256"
    mode: str | None = None  # e.g. "CBC", "GCM"
    library: str | None = None  # e.g. "OpenSSL EVP", "Windows CNG (BCrypt)"
    key_source: str | None = None
    key_management: str | None = None
    iv: str | None = None
    file_marker: str | None = None
    extension: str | None = None  # appended extension, e.g. ".MEDUSA"
    partial_threshold: str | None = None  # e.g. "files > 8 MB partially encrypted"
    per_file_key: bool | None = None
    evidence_ref: str | None = None


class RansomNote(BaseModel):
    """Extracted ransom-note artefact (reference IV.1)."""

    model_config = _STRICT_CONFIG

    filename: str | None = None
    verbatim_content: str | None = None
    sections: list[str] = Field(default_factory=list)
    company_id_hash: str | None = None


class TechnicalSubsection(BaseModel):
    """A free-prose technical-spine subsection authored by the Composer.

    Used for the narrative subsections that don't warrant their own typed model
    (packing/obfuscation, string resolution, discovery, persistence detail,
    message/packet structure, evasion/anti-forensics). ``body`` is empty when no
    evidence supports the subsection; the renderer then states absence.
    """

    model_config = _STRICT_CONFIG

    title: str
    body: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class TechnicalAnalysis(BaseModel):
    """The report's technical-analysis spine (reference §8)."""

    model_config = _STRICT_CONFIG

    packing_obfuscation: TechnicalSubsection | None = None
    cli_flags: list[CliFlag] = Field(default_factory=list)
    string_resolution: TechnicalSubsection | None = None
    discovery: TechnicalSubsection | None = None
    service_process_kill: ServiceProcessKill | None = None
    shadow_copy_destruction: list[str] = Field(default_factory=list)  # verbatim commands
    encryption_scheme: EncryptionScheme | None = None
    persistence_detail: TechnicalSubsection | None = None
    message_packet_structure: TechnicalSubsection | None = None
    evasion_antiforensics: TechnicalSubsection | None = None
    ransom_note: RansomNote | None = None


class C2Channel(BaseModel):
    """One command-and-control channel (reference §9)."""

    model_config = _STRICT_CONFIG

    name: str
    protocol: str | None = None
    encryption: str | None = None
    packet_layout: str | None = None
    beacon_format: str | None = None
    evidence_ref: str | None = None


class ConsolidatedIOC(BaseModel):
    """One row of the consolidated, typed, defanged IOC table (reference §11)."""

    model_config = _STRICT_CONFIG

    type: str  # Domain / C2 URL / IPv4 / Registry Key / Path / File / Mutex / Filename / Hash
    description: str = ""
    value: str  # defanged
    is_network: bool = False


class Figure(BaseModel):
    """A deterministic figure embedded in the report (reference Part V).

    ``content`` holds inline SVG (charts/diagrams) or ``<pre>`` text (Ghidra
    listings). No fake screenshots — every figure is generated from real data.
    """

    model_config = _STRICT_CONFIG

    id: str
    caption: str
    kind: Literal[
        "process_tree",
        "attack_matrix",
        "entropy_chart",
        "network_graph",
        "infection_chain",
        "code_listing",
    ]
    content: str  # inline SVG or <pre> HTML
    legend: str | None = None


class Conclusion(BaseModel):
    """Graded closing assessment (reference §10)."""

    model_config = _STRICT_CONFIG

    sophistication_rating: str | None = None  # e.g. "medium sophistication"
    text: str = ""


# ---------------------------------------------------------------------------
# Top-level report
# ---------------------------------------------------------------------------


class MalwareReport(BaseModel):
    """Comprehensive malware analysis report — the public contract.

    Consumed by:
      - CLI ``--report`` flag (markdown render)
      - REST API (``/reports/{id}/full``)
      - Frontend tab UI (Identity / Static / Dynamic / Network / ...)
      - DB JSONB column ``analysis_reports.malware_report``
      - Enrichment worker (mutates ``network.*.reputation``, ``attribution.similar_samples``)
    """

    model_config = _PERMISSIVE_CONFIG

    schema_version: Literal["1.0"] = "1.0"
    generated_at: datetime = Field(default_factory=get_utcnow)

    # --- Verdict & severity ---
    verdict: Literal["Malware", "Suspicious", "Benign"] = "Suspicious"
    overall_confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    malware_category: str | None = None
    severity: SeverityAssessment = Field(default_factory=SeverityAssessment)

    # --- Degraded-run signalling ---
    # True when the run had low/no analyst data (e.g. all LLM analysts errored,
    # sandbox observed nothing, only Layer-0 rule matches). The report renders a
    # prominent banner so a numerically high verdict/severity is not read as
    # authoritative. ``degradation_reasons`` carries human-readable causes.
    degraded_mode: bool = False
    degradation_reasons: list[str] = Field(default_factory=list)

    # --- Identification ---
    identity: SampleIdentity

    # --- Deterministic analyses ---
    static: StaticAnalysis | None = None
    dynamic: DynamicBehavior | None = None
    network: NetworkIOCs | None = None
    persistence: list[PersistenceMechanism] = Field(default_factory=list)
    capability_matrix: list[CapabilityCell] = Field(default_factory=list)
    ttp_mappings: list[TTPMapping] = Field(default_factory=list)

    # --- Attribution ---
    attribution: FamilyAttribution = Field(default_factory=FamilyAttribution)

    # --- LLM-generated narrative ---
    executive_summary: str = ""
    capabilities_narrative: list[str] = Field(default_factory=list)
    defensive_recommendations: list[DefensiveRecommendation] = Field(default_factory=list)

    # --- Detection content ---
    detection_signatures: list[DetectionRule] = Field(default_factory=list)

    # --- Pipeline observability ---
    run_summary: dict[str, Any] = Field(default_factory=dict)
    negotiation_summary: dict[str, Any] = Field(default_factory=dict)

    # --- IOC export ---
    stix_bundle_extended: dict[str, Any] = Field(default_factory=dict)
    misp_attributes: list[dict[str, Any]] | None = None

    # --- References ---
    references: list[ExternalReference] = Field(default_factory=list)

    # --- Captured tool evidence (report-reshaping Phase 1) ---
    # Per-agent list of captured ReAct tool outputs (decompiled functions,
    # crypto constants, emulation/dataflow traces) — the durable raw material
    # the report Composer grounds the deep technical spine in. Size-capped
    # upstream (see ``schemas.tool_evidence``); kept out of the STIX / FP-linter
    # paths. Empty on legacy rows and mock runs.
    technical_evidence: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)

    # --- Professional-report front-matter & spine (report-reshaping Phase 2) ---
    # All additive/optional. Deterministic extractors fill front_matter /
    # version_history / consolidated_iocs; the section-wise Composer fills the
    # prose (technical spine, intro, conclusion, C2). Empty/None until Phase 3-4
    # populate them — legacy consumers ignore unknown fields.
    front_matter: ReportFrontMatter | None = None
    version_history: list[VersionHistoryEntry] = Field(default_factory=list)
    tlp: TLPLevel = "CLEAR"
    intro_background: str = ""
    technical_analysis: TechnicalAnalysis | None = None
    c2_channels: list[C2Channel] = Field(default_factory=list)
    conclusion: Conclusion | None = None
    consolidated_iocs: list[ConsolidatedIOC] = Field(default_factory=list)
    figures: list[Figure] = Field(default_factory=list)
    appendices: list[str] = Field(default_factory=list)
    disclaimer: str | None = None
    acknowledgements: str | None = None


# Resolve the recursive ``ProcessNode.children`` forward reference.
ProcessNode.model_rebuild()
