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
    obfuscation_indicators: list[str] = Field(default_factory=list)


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
    # supporting source (Triage CTI ``family[]``, sandbox signature, or
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
    # Family-feature RAG candidates — families retrieved by static-feature
    # similarity to a reference fingerprint KB, surfaced as evidence the LLM
    # weighed (sibling of function_hash_matches). Each row: family, similarity,
    # malware_category, sample_count, match_method, source. Populated by the report
    # node from the judge node's RAG pass (empty unless the RAG is enabled and a
    # fingerprint catalog is present).
    family_rag_candidates: list[dict[str, Any]] = Field(default_factory=list)


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


class ExternalReference(BaseModel):
    """Outbound link in the report references section."""

    model_config = _STRICT_CONFIG

    source: str  # "VirusTotal", "MalwareBazaar", "MITRE ATT&CK", ...
    url: str
    note: str | None = None


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


# Resolve the recursive ``ProcessNode.children`` forward reference.
ProcessNode.model_rebuild()
