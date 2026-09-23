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
    """The judge's severity rating, with its rationale and the affected platforms."""

    # Permissive on purpose: every report stored before the score was dropped
    # carries ``overall_score``, a number the builder derived from the rating
    # and no model ever stated. The key is ignored on load rather than kept as
    # a field nothing writes.
    model_config = _PERMISSIVE_CONFIG

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
    # SHA-1 over the signer certificate, which is how Windows, VirusTotal and
    # every signing-certificate feed name one. The identifier the subject and
    # issuer above were read from.
    signer_thumbprint: str | None = None
    signature_valid: bool | None = None
    # The pack's ``signing_info`` entry these facts were read from.
    evidence_id: str | None = None


# Canonical platform vocabulary. Used by SampleIdentity, the Sigma and YARA
# scanning tools, and the FP linter. "multi" is for samples
# that don't bind to one OS (a JAR, a macro document, a PDF). "unknown" is the
# conservative default when magic bytes don't identify the format and the
# sandbox couldn't disambiguate either.
#
# The type is a plain ``str`` rather than a Literal: routing must never refuse
# a sample because its platform is not in a closed set, so an operator's own
# vocabulary passes through and only degrades the rule filtering that reads it.
# ``KNOWN_PLATFORMS`` is what the inference layer emits and what the UI labels.
Platform = str

KNOWN_PLATFORMS: tuple[str, ...] = (
    "windows",
    "linux",
    "macos",
    "android",
    "ios",
    "multi",
    "unknown",
)


class SampleIdentity(BaseModel):
    """Everything needed to uniquely identify the sample on disk and in CTI."""

    model_config = _STRICT_CONFIG

    hashes: FileHashes
    file_name: str | None = None
    file_size_bytes: int = 0
    file_type: str = "unknown"
    # The canonical platform inferred from file_type with sandbox fallback.
    # Drives Sigma and YARA rule filtering, and the FP linter's check that a
    # reported technique can run on this sample at all.
    platform: Platform = "unknown"
    mime_type: str | None = None
    magic_bytes: str = ""  # hex string of first 16 bytes
    compile_timestamp: datetime | None = None
    language_or_compiler: str | None = None
    signing: SignatureInfo = Field(default_factory=SignatureInfo)
    # What the format tool read out of the header, stated as facts beside the
    # file type: the machine it was built for, whether it is a library, and
    # the names the binary gives itself. A DLL carrying an ``.exe`` name is a
    # fact a reader needs before they try to run it, and the export
    # directory's own name is often the family's internal one. ``None`` when
    # no format tool answered, on a report stored before these existed too.
    architecture: str | None = None
    is_dll: bool | None = None
    internal_name: str | None = None
    export_name: str | None = None


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

    # Permissive on purpose: a report written while the extractor labelled
    # imports carries ``is_suspicious`` and ``category`` on every row. Those
    # keys are ignored on load rather than kept as fields nothing writes; what
    # an import means is stated by the pack's ``api_capability`` entry now.
    model_config = _PERMISSIVE_CONFIG

    dll: str
    function: str


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


class ExportRow(BaseModel):
    """One exported symbol as the export directory states it."""

    model_config = _STRICT_CONFIG

    name: str
    ordinal: int | None = None
    # Hex string, e.g. ``"0x3ce4"``. Printed beside the name because several
    # exports sharing one address is itself a finding a reader should see.
    rva: str | None = None


class StaticAnalysis(BaseModel):
    """Findings from binary parsing / disassembly (no execution)."""

    model_config = _STRICT_CONFIG

    sections: list[PESection] = Field(default_factory=list)
    imports: list[ImportRow] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    # The same exports with their ordinal and address, when the format tool
    # reported them. ``exports`` stays the plain list every older consumer and
    # every stored report reads.
    export_rows: list[ExportRow] = Field(default_factory=list)
    interesting_strings: list[StringIOC] = Field(default_factory=list)
    embedded_resources: list[dict[str, Any]] = Field(default_factory=list)
    packer_hint: str | None = None
    # Ranked packer/protector identifications: {name, kind, confidence, method,
    # evidence}. `packer_hint` is the display string derived from the top row.
    # The list exists because a *confidence* is what downstream needs — the
    # T1027 over-claim cap keys on "is this really packed", and a bare
    # non-None string cannot answer that.
    packer_matches: list[dict[str, Any]] = Field(default_factory=list)
    # The linker's debug PDB path, e.g.
    # ``E:\build-dir\CODRU-CL23M-SOURCES\bin\Win32\Release\BdUserHost.pdb``.
    # One field carrying the build machine's layout, the internal project name,
    # the architecture and the build configuration — and the internal name is
    # often the family's own before the industry picked one.
    pdb_path: str | None = None
    obfuscation_indicators: list[str] = Field(default_factory=list)
    # {behaviour_category: count} over the import table, as the knowledge table
    # stated it when the triage pack asked (``tools.knowledge.api_capability``).
    # ``api_capabilities_evidence_ids`` names the ledger entries it was counted
    # from, so the profile line in the report points at rows a reader can open.
    api_capabilities: dict[str, int] = Field(default_factory=dict)
    api_capabilities_evidence_ids: list[str] = Field(default_factory=list)
    # {behaviour_category: share of a named benign corpus the category appears
    # on}, recorded from the same answer. A count of imports in a category is
    # not a fact about the sample until a reader knows that ``execution`` is on
    # 93.5% of ordinary Windows software and ``keylogging`` on 4.0%; a profile
    # line without it is the last place this layer prints a number with nothing
    # to weigh it against. ``api_capability_corpus`` names what the shares are
    # of, once, because the same sentence under eight categories is eight
    # copies of one fact. Empty on a report stored before the field existed,
    # and the surfaces then print the counts alone as they always did.
    api_capability_rates: dict[str, float] = Field(default_factory=dict)
    api_capability_corpus: str = ""
    # The audit trail behind a rule-derived technique: one row per rule that
    # fired over the import table — capa's, or the knowledge table's technique
    # rules — with the imports or namespaces that evidenced it and, for the
    # pack's rows, the ledger id. Without this a reader sees a technique in the
    # report and has no way to check the reasoning.
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
    # Sections this sandbox structurally cannot produce, e.g. ["apistats",
    # "calls", "registry", "generic_events"] for Hatching Triage. Named rather
    # than left empty: an empty API-call table reads as "the sample did
    # nothing", which is the opposite of "we could not see". Every renderer
    # prints "Not provided by this sandbox" for these, and no detection layer
    # treats them as negative evidence.
    unavailable: list[str] = Field(default_factory=list)


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
    # Where the name came from. ``sandbox`` is a resolution or a request the
    # sample actually made, ``analyst`` an agent's own artefact, ``strings`` a
    # run of bytes in the file that has the shape of a hostname — which is a
    # far weaker claim and was being published as though it were the same one.
    # ``None`` for a producer that does not record it.
    source: Literal["sandbox", "analyst", "strings"] | None = None
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
    # Where the address came from, with the same three answers and the same
    # weight a domain's and a URL's carry. The string sweep turns any run of
    # digits with dots in it into an address — one live bundle published
    # ``6.0.0.0``, a version number out of the strings table — and until this
    # the addresses were the one network kind nothing asked about.
    # ``None`` for a producer that does not record it.
    source: Literal["sandbox", "analyst", "strings"] | None = None
    reputation: dict[str, Any] | None = None


class NetworkURL(BaseModel):
    """Observed HTTP request URL."""

    model_config = _STRICT_CONFIG

    url: str
    method: str = "GET"
    status: int | None = None
    user_agent: str | None = None
    # Where the URL came from, with the same three answers and the same weight
    # a domain's ``source`` carries. A run of bytes in the file that has the
    # shape of a URL is a far weaker claim than a request the sample made, and
    # the two were being published as though they were the same one.
    # ``None`` for a producer that does not record it.
    source: Literal["sandbox", "analyst", "strings"] | None = None


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

    # One vocabulary per platform the router accepts. A Windows-only list made
    # every macOS launch agent and every Android boot receiver arrive as
    # "other", which is the same as not reporting the mechanism at all: the
    # kind is what a reader scans for and what the technique id is checked
    # against.
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
        # ── Linux (ELF) ──────────────────────────────────────
        "systemd_service",
        "systemd_timer",
        "cron_job",
        "init_d",
        "rc_local",
        "ld_preload",
        "xdg_autostart",
        "shell_profile",
        "udev_rule",
        "kernel_module",
        # ── macOS (Mach-O) ───────────────────────────────────
        "launch_agent",
        "launch_daemon",
        "login_item",
        "kernel_extension",
        "configuration_profile",
        # ── Android (APK/DEX) ────────────────────────────────
        "boot_receiver",
        "device_admin",
        "accessibility_service",
        "foreground_service",
        "work_scheduler",
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


def confidence_text(value: float | None) -> str:
    """A technique's confidence as a report prints it: "not given" when none was."""
    return "not given" if value is None else f"{value:.2f}"


class CapabilityCell(BaseModel):
    """One cell in the tactic×technique heatmap."""

    model_config = _STRICT_CONFIG

    tactic: str  # ATT&CK tactic ID, e.g. "TA0002"
    tactic_name: str
    technique_id: str  # e.g. "T1055"
    technique_name: str
    evidence: list[str] = Field(default_factory=list)
    # The highest number a source put on the technique, or ``None`` when no
    # source gave one — printed "not given", never as a confidence of zero.
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    # Who stated ``confidence``: "the judge", "the static analyst". Empty when
    # no source gave a number and on a row stored before it was recorded.
    confidence_source: str = ""
    contributing_layers: list[str] = Field(default_factory=list)
    # ``False`` when the ATT&CK catalogue has no entry for this id and the
    # producer kept it after being told. The row stays — deleting an analyst's
    # answer is what this pipeline stopped doing — and every renderer prints
    # the marker beside it. Defaults ``True`` so rows persisted before the flag
    # existed keep their meaning.
    technique_id_valid: bool = True
    # The catalogue's own scope for the technique: the ATT&CK domain that owns
    # it and the platforms it declares. Filled from the catalogue by the
    # matrix builder; empty when the catalogue had nothing to say. The FP
    # linter's platform check reads them.
    platforms: list[str] = Field(default_factory=list)
    domain: str = ""
    # Why this technique is not in ``ttp_mappings``, in words, and empty when
    # it is. Two rules put a sentence here: an id the ATT&CK catalogue has no
    # entry for, and one whose domain or platforms the sample cannot host
    # after the producer was told and kept it. The row itself stays exactly as
    # the producer wrote it — this says what the report did with it.
    not_published: str = ""


class TTPMapping(BaseModel):
    """Detailed technique→evidence record, richer than ``CapabilityCell``."""

    model_config = _STRICT_CONFIG

    technique_id: str
    technique_name: str
    tactic: str = ""
    tactic_name: str = ""
    evidence_quotes: list[str] = Field(default_factory=list)
    # See ``CapabilityCell.confidence``: ``None`` when no source gave a number.
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    contributing_layers: list[str] = Field(default_factory=list)
    is_corroborated: bool = False
    # See ``CapabilityCell.technique_id_valid``.
    technique_id_valid: bool = True


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


class FamilyAttribution(BaseModel):
    """Best-guess malware family / actor / campaign attribution."""

    # Permissive on purpose: every report written before the in-process
    # case-prior retrieval went carries ``attck_case_candidates`` (usually
    # ``[]``). The key is ignored on load rather than kept as a field nothing
    # writes.
    model_config = _PERMISSIVE_CONFIG

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
    # The ledger entries the judge cited for the name, and who named it:
    # ``judge`` when the judge's assessment carried it, ``sandbox`` when the
    # judge abstained and the sandbox's own ``cti.family[]`` supplied it.
    # Empty and ``None`` on a report stored before either was recorded.
    family_evidence_ids: list[str] = Field(default_factory=list)
    family_source: Literal["judge", "sandbox"] | None = None
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
    # Link each recommendation to the ATT&CK technique it
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
# Professional-report front-matter & technical spine
# ---------------------------------------------------------------------------
#
# Additive, all-optional containers modelled on the reference spec at
# other/docs/report-reference/malware-analysis-report-reference.md. Deterministic
# extractors fill the front-matter / IOC / fingerprint fields; the
# section-wise Composer fills the prose subsections, each grounded in
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


class FlowStep(BaseModel):
    """One step of what the sample does from its entry point to steady state.

    ``voice`` is the report model's own mark: ``observed`` for a step a sandbox
    watched, ``assessed`` for one read from the code or inferred. The renderer
    prints the mark as written; the validation loop asks the model once when an
    ``observed`` step cites no sandbox entry and records it if the step stays.
    """

    model_config = _STRICT_CONFIG

    order: int
    action: str
    voice: Literal["observed", "assessed"] = "assessed"
    evidence_refs: list[str] = Field(default_factory=list)


class ConfigItem(BaseModel):
    """One configuration value the report model recovered, and how."""

    model_config = _STRICT_CONFIG

    key: str
    value: str
    how_obtained: Literal["decrypted", "observed", "static-string", "inferred"] = "inferred"
    evidence_refs: list[str] = Field(default_factory=list)


class HostIdentifier(BaseModel):
    """One identifier the report model read that a responder can look for on a host.

    What it is in a responder's words, the value as the entry it was read in
    records it, what the sample uses it for where the evidence says, and the
    entries it was read in. Model-written and printed as written; the platform
    copies no string into it.
    """

    model_config = _STRICT_CONFIG

    kind: str
    value: str
    purpose: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class CommandRow(BaseModel):
    """One command the sample accepts from its operator."""

    model_config = _STRICT_CONFIG

    id: str | None = None
    name: str
    description: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class TechnicalAnalysis(BaseModel):
    """The report's technical-analysis spine (reference §8)."""

    model_config = _STRICT_CONFIG

    # Ordered steps from entry to steady state, the configuration table and the
    # command table: model-written, printed as written, absent when the report
    # model supplied none.
    execution_flow: list[FlowStep] = Field(default_factory=list)
    configuration: list[ConfigItem] = Field(default_factory=list)
    # The identifiers a responder searches a host for — names, paths, keys,
    # strings — as the report model read them, each citing its entry.
    host_identifiers: list[HostIdentifier] = Field(default_factory=list)
    commands: list[CommandRow] = Field(default_factory=list)
    command_and_control: TechnicalSubsection | None = None
    payloads: TechnicalSubsection | None = None
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
    # The hosts, addresses or URLs the channel talks to, as the model wrote
    # them, and the entries it cited. The report prints each endpoint defanged
    # and says beside it whether the run may publish it.
    endpoints: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class JudgeIndicator(BaseModel):
    """One value a judge indicator names: its IOC kind, the value, a hash's algorithm."""

    model_config = _STRICT_CONFIG

    kind: str
    value: str
    algorithm: str = ""


class ConsolidatedIOC(BaseModel):
    """One row of the consolidated, typed IOC table.

    ``value`` is live, like every other value in the JSON report: the
    human-readable renderings defang it by ``kind`` when they print it. A row
    stored before ``kind`` existed carries the value the old table wrote,
    already defanged, and is printed as stored.
    """

    model_config = _STRICT_CONFIG

    type: str  # SHA-256 / Domain / URL / IPv4 / Registry Key / Path / Mutex / Scheduled task / …
    description: str = ""
    value: str
    is_network: bool = False
    # The indicator kind the defanging and the publish rule are keyed on
    # (``domain``, ``ip``, ``url``, ``email``, ``path``, ``registry``, ``mutex``,
    # ``hash``, …), who recorded the row (``identity``, ``sandbox``,
    # ``analyst``, ``judge``, ``strings``, ``persistence``), what else is known
    # about it, and the one publish rule's answer: ``yes`` or ``no: <reason>``.
    kind: str | None = None
    source: str | None = None
    context: str = ""
    published: str | None = None


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
    """Graded closing assessment, as stored by reports written before it was dropped.

    Nothing writes this now. A stored report's ``sophistication_rating`` is
    printed beside the verdict; its text restated the summary and is not.
    """

    model_config = _STRICT_CONFIG

    sophistication_rating: str | None = None  # e.g. "medium sophistication"
    text: str = ""


class KeyFinding(BaseModel):
    """One key-finding bullet, written by the report model with its citations."""

    model_config = _STRICT_CONFIG

    text: str
    evidence_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Evidence-built sections
# ---------------------------------------------------------------------------


class EvidenceSection(BaseModel):
    """One report section built from what the tools and the agents produced.

    The typed blocks above model the shapes this project knew in advance: a PE
    section table, a process tree, a persistence mechanism. A tool server
    nobody has written yet produces shapes nothing here models, and a report
    that could only print what it modelled would silently drop them.

    So a section carries its own shape — a table, a key/value block, a list or
    a paragraph — and, more importantly, the ledger entry ids it was built
    from. ``evidence_ids`` is what makes the section checkable: a reader can
    ask the evidence endpoint for ``ev_0007`` and see the call the row came
    out of. A section with neither an evidence id nor a ``source`` naming the
    finding it came from is counted in the run summary and is a defect.
    """

    model_config = _STRICT_CONFIG

    key: str
    title: str
    kind: Literal["table", "kv", "text", "list"] = "text"
    columns: list[str] = Field(default_factory=list)
    rows: list[list[str]] = Field(default_factory=list)
    text: str = ""
    items: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    # Where the section came from: ``tool``, ``routing``, ``agent`` or
    # ``agent:<name>``. Read by the grounding check, which accepts a finding
    # source in place of an evidence id.
    source: str = ""


class EvidenceIndexRow(BaseModel):
    """One line of the report's index of the calls behind it.

    Deliberately without the output: the report says which call happened, how
    long it took and whether it worked, and the evidence endpoint serves what
    it returned. Embedding every output would put the whole ledger inside the
    report's JSONB column twice.
    """

    model_config = _STRICT_CONFIG

    id: str
    agent: str = ""
    server: str | None = None
    tool: str = ""
    ok: bool = True
    duration_ms: int = 0
    truncated: bool = False


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
    # ``None`` when nothing assessed a confidence — a verdict the pipeline
    # wrote itself because the judge never answered. It is not defaulted to
    # 0.0 for the same reason ``severity`` is not defaulted to "Informational":
    # a confidence of zero is an assessment, and printing one for a report that
    # has none says the run was certain it knew nothing.
    overall_confidence: Annotated[float | None, Field(ge=0.0, le=1.0)] = 0.0
    malware_category: str | None = None
    # ``None`` when the judge assessed no severity. It is not defaulted to
    # "Informational": an unassessed report and a report assessed as harmless
    # are different findings, and a default would print the second for the first.
    severity: SeverityAssessment | None = None

    # --- Degraded-run signalling ---
    # True when the run had little or no analyst data — every LLM analyst
    # errored, the sandbox was unreachable, the container could not be opened.
    # The judge is told the same reasons in its verdict prompt and sets its
    # confidence knowing them; the report renders a prominent banner so a
    # reader sees why. ``degradation_reasons`` carries the human-readable list.
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
    # The published technique list. Every other technique surface is built from
    # it — the report's ATT&CK section, its References, the STIX
    # attack-patterns, ``/reports/{id}/mitre`` — so a technique appears in all
    # of them or in none, and an id the ATT&CK check rejected appears in none.
    ttp_mappings: list[TTPMapping] = Field(default_factory=list)
    # What the judge named as an attack-pattern without naming a technique id,
    # after being asked for one. A behaviour, reported as a behaviour: it is
    # never published as an ATT&CK technique, and it is not dropped either.
    unmapped_behaviours: list[str] = Field(default_factory=list)

    # --- Attribution ---
    attribution: FamilyAttribution = Field(default_factory=FamilyAttribution)

    # --- LLM-generated narrative ---
    executive_summary: str = ""
    # Three to six bullets the report leads with, from the same narrative
    # round as the summary. Empty when the report model wrote none.
    key_findings: list[KeyFinding] = Field(default_factory=list)
    # Written by no code now: the technical-analysis subsections carry what
    # these paragraphs used to. Kept so a report stored before the change
    # still prints its paragraphs, under the technical analysis's lead-in.
    capabilities_narrative: list[str] = Field(default_factory=list)
    defensive_recommendations: list[DefensiveRecommendation] = Field(default_factory=list)

    # --- Detection content ---
    detection_signatures: list[DetectionRule] = Field(default_factory=list)

    # --- Pipeline observability ---
    run_summary: dict[str, Any] = Field(default_factory=dict)
    negotiation_summary: dict[str, Any] = Field(default_factory=dict)

    # --- IOC export ---
    stix_bundle_extended: dict[str, Any] = Field(default_factory=dict)
    # The values the judge's own indicators name, one per single-comparison
    # pattern, as the judge wrote them. Read by the IOC table and ``/iocs``,
    # which ask the one publish rule of each exactly as the export does; empty
    # on a report stored before the field existed.
    judge_indicators: list[JudgeIndicator] = Field(default_factory=list)
    # For each technique a YARA rule of this run asserted, the rules and how
    # many of each rule's own strings matched (``{"rule", "strings"}``), as the
    # scan answered. Read by the ATT&CK table's "rule match only" note and by
    # the capability grounding; empty on a report stored before it existed.
    rule_match_strings: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    misp_attributes: list[dict[str, Any]] | None = None

    # --- References ---
    references: list[ExternalReference] = Field(default_factory=list)

    # --- Captured tool evidence ---
    # Per-agent list of captured ReAct tool outputs (decompiled functions,
    # crypto constants, emulation/dataflow traces) — the durable raw material
    # the report Composer grounds the deep technical spine in. Size-capped
    # upstream (see ``schemas.tool_evidence``); kept out of the STIX / FP-linter
    # paths. Empty on legacy rows and mock runs.
    technical_evidence: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)

    # --- Sections built from the evidence ledger ---
    # Everything the tools and the agents produced that the typed blocks above
    # have no field for, each carrying the ledger ids it was built from. The
    # renderers print these after the typed sections; ``evidence_index`` is the
    # list of calls behind them, without their outputs.
    sections: list[EvidenceSection] = Field(default_factory=list)
    evidence_index: list[EvidenceIndexRow] = Field(default_factory=list)

    # --- Professional-report front-matter & spine ---
    # All additive/optional. Deterministic extractors fill front_matter /
    # version_history / consolidated_iocs; the section-wise Composer fills the
    # prose (execution flow, technical spine, background, C2). Empty/None until those
    # steps populate them — legacy consumers ignore unknown fields.
    front_matter: ReportFrontMatter | None = None
    version_history: list[VersionHistoryEntry] = Field(default_factory=list)
    tlp: TLPLevel = "CLEAR"
    intro_background: str = ""
    technical_analysis: TechnicalAnalysis | None = None
    c2_channels: list[C2Channel] = Field(default_factory=list)
    # Written by no code now; a stored report keeps its sophistication rating.
    conclusion: Conclusion | None = None
    consolidated_iocs: list[ConsolidatedIOC] = Field(default_factory=list)
    figures: list[Figure] = Field(default_factory=list)
    appendices: list[str] = Field(default_factory=list)
    disclaimer: str | None = None
    acknowledgements: str | None = None


# Resolve the recursive ``ProcessNode.children`` forward reference.
ProcessNode.model_rebuild()
