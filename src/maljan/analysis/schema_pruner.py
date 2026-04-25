"""Dynamic schema pruning for STIX output quality improvement.

Phase 7.1 implementation — CTI-GEN (IEEE CSR 2025) methodology.

Problem: The JudgeAgent's give_verdict() calls llm.with_structured_output(Bundle),
which exposes the LLM to the full STIX schema (all SDO types). This causes:
  - The LLM to produce irrelevant objects (e.g. network traffic for ransomware)
  - Diluted attention across type choices it will never need
  - Lower relationship F1 (literature baseline: 57% without pruning)

Solution: Infer the malware category from ISR reports and inject a
STIX object type recommendation block into the judge prompt. The LLM is
guided to produce only the object types relevant to the detected category,
reducing hallucination and improving output coherence.

Design decisions:
  - Inference is keyword-scoring (no LLM call, no dependency). Fast and
    deterministic. Purpose is not perfect classification — even rough
    category signal meaningfully improves type focus.
  - Schema pruning is PROMPT-level only (not Pydantic schema restriction).
    The Bundle model still accepts all types; the hint is advisory.
  - Unknown/tie → no pruning (safe default, full type set).
  - Weights: ATT&CK technique IDs score highest (most specific signal),
    domain-specific terms score medium, generic terms score low.

Exported API:
    MalwareCategory               — enum of supported categories
    infer_malware_category()      — category detection from reports + ISRs
    get_pruned_schema_hint()      — prompt-ready recommendation block
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from maljan.schemas.isr_models import AgentISR


# ---------------------------------------------------------------------------
# Category enum
# ---------------------------------------------------------------------------

class MalwareCategory(StrEnum):
    """Supported malware behavioral categories for schema pruning."""

    RANSOMWARE = "ransomware"
    RAT = "rat"          # Remote Access Trojan / Backdoor
    DROPPER = "dropper"  # Loader / Downloader / Stager
    WORM = "worm"        # Self-propagating
    INFOSTEALER = "infostealer"
    UNKNOWN = "unknown"  # Fallback — no pruning applied


# ---------------------------------------------------------------------------
# Keyword scoring tables
# Each entry: (keyword, weight)
# Higher weight = more specific / reliable signal
# ---------------------------------------------------------------------------

_CATEGORY_KEYWORDS: dict[MalwareCategory, list[tuple[str, float]]] = {
    MalwareCategory.RANSOMWARE: [
        # ATT&CK technique IDs — most specific signal
        ("t1486", 3.0),   # Data Encrypted for Impact
        ("t1490", 3.0),   # Inhibit System Recovery
        ("t1489", 2.5),   # Service Stop
        ("t1485", 2.5),   # Data Destruction
        # Domain terms
        ("encrypt", 2.0),
        ("ransom", 3.0),
        ("decrypt", 2.0),
        ("aes", 1.5),
        ("rsa", 1.5),
        ("chacha20", 2.0),
        ("bitcoin", 2.5),
        ("monero", 2.5),
        ("wallet", 2.0),
        ("extension", 1.0),
        (".locked", 2.0),
        (".enc", 1.5),
        ("shadow copy", 2.0),
        ("vssadmin", 2.5),
        ("wbadmin", 2.0),
        ("bcdedit", 2.0),
        ("ransom note", 3.0),
        ("readme.txt", 1.5),
        ("how_to_decrypt", 2.5),
    ],
    MalwareCategory.RAT: [
        # ATT&CK technique IDs
        ("t1095", 3.0),   # Non-Application Layer Protocol (C2)
        ("t1071", 2.5),   # Application Layer Protocol (C2)
        ("t1571", 2.5),   # Non-Standard Port
        ("t1105", 2.0),   # Ingress Tool Transfer
        ("t1059", 2.0),   # Command and Scripting Interpreter
        # Domain terms
        ("remote access", 2.5),
        ("backdoor", 3.0),
        ("c2", 2.0),
        ("command and control", 3.0),
        ("reverse shell", 3.0),
        ("bind shell", 2.5),
        ("beacon", 2.5),
        ("implant", 2.0),
        ("rat", 2.0),
        ("keylog", 2.0),
        ("screenshot", 1.5),
        ("remote desktop", 1.5),
        ("rdp", 1.5),
        ("shellcode", 2.0),
    ],
    MalwareCategory.DROPPER: [
        # ATT&CK technique IDs
        ("t1105", 3.0),   # Ingress Tool Transfer
        ("t1218", 2.5),   # System Binary Proxy Execution
        ("t1059", 2.0),   # Command and Scripting Interpreter
        ("t1027", 2.0),   # Obfuscated Files
        ("t1140", 2.0),   # Deobfuscate/Decode Files
        # Domain terms
        ("dropper", 3.0),
        ("loader", 3.0),
        ("downloader", 2.5),
        ("stage", 2.0),
        ("payload", 2.0),
        ("download", 2.0),
        ("urldownloadtofile", 3.0),
        ("bitsadmin", 2.5),
        ("certutil", 2.5),
        ("mshta", 2.5),
        ("regsvr32", 2.0),
        ("rundll32", 2.0),
        ("packed", 1.5),
        ("obfuscat", 1.5),
        ("unpacking", 2.0),
    ],
    MalwareCategory.WORM: [
        # ATT&CK technique IDs
        ("t1021", 3.0),   # Remote Services (lateral movement)
        ("t1091", 3.0),   # Replication Through Removable Media
        ("t1570", 2.5),   # Lateral Tool Transfer
        ("t1080", 2.5),   # Taint Shared Content
        # Domain terms
        ("worm", 3.0),
        ("propagat", 3.0),
        ("self-replicate", 3.0),
        ("replicate", 2.0),
        ("network share", 2.5),
        ("smb", 2.0),
        ("\\ipc$", 2.5),
        ("removable", 2.0),
        ("usb", 2.0),
        ("autorun", 2.5),
        ("spread", 2.0),
        ("infect", 2.0),
        ("lateral movement", 2.5),
    ],
    MalwareCategory.INFOSTEALER: [
        # ATT&CK technique IDs
        ("t1003", 3.0),   # OS Credential Dumping
        ("t1056", 3.0),   # Input Capture
        ("t1555", 3.0),   # Credentials from Password Stores
        ("t1041", 2.5),   # Exfiltration Over C2 Channel
        ("t1567", 2.5),   # Exfiltration Over Web Service
        # Domain terms
        ("steal", 2.5),
        ("credential", 2.5),
        ("password", 2.0),
        ("keylog", 3.0),
        ("clipboard", 2.0),
        ("browser", 1.5),
        ("cookie", 1.5),
        ("mimikatz", 3.0),
        ("lsass", 3.0),
        ("ntds.dit", 3.0),
        ("sam database", 2.5),
        ("exfiltrat", 2.5),
        ("upload", 1.5),
        ("data theft", 2.5),
    ],
}

# ---------------------------------------------------------------------------
# Per-category STIX prompt hints
# Tuple: (focus_types list, avoid_hint, technique_focus, narrative_hint)
# ---------------------------------------------------------------------------

_CATEGORY_HINTS: dict[MalwareCategory, dict] = {
    MalwareCategory.RANSOMWARE: {
        "focus_types": [
            "Malware — the ransomware sample",
            "AttackPattern — encryption, recovery inhibition, service disruption TTPs",
            "Indicator — encrypted file extensions, ransom note filenames, mutex names",
            "ConfidenceAnnotatedRelationship — Malware uses AttackPattern",
        ],
        "deprioritize": "Network infrastructure (ransomware typically has minimal C2)",
        "technique_focus": "T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), "
                           "T1489 (Service Stop), T1485 (Data Destruction)",
        "narrative": "Focus on encryption mechanism, key management, file targeting scope, "
                     "recovery prevention methods, and ransom payment infrastructure.",
    },
    MalwareCategory.RAT: {
        "focus_types": [
            "Malware — the RAT/backdoor implant",
            "AttackPattern — C2 communication, remote execution, persistence TTPs",
            "Indicator — C2 domain/IP patterns, beacon intervals, mutex names",
            "ConfidenceAnnotatedRelationship — Malware uses AttackPattern, "
            "Malware communicates-with infrastructure",
        ],
        "deprioritize": "File encryption or mass file operations",
        "technique_focus": "T1095 (Non-Application Layer Protocol), T1071 (App Layer Protocol), "
                           "T1059 (Command and Scripting Interpreter), T1547 (Persistence)",
        "narrative": "Focus on C2 channel, authentication, supported commands, "
                     "persistence mechanism, and anti-analysis techniques.",
    },
    MalwareCategory.DROPPER: {
        "focus_types": [
            "Malware — the dropper/loader stage",
            "AttackPattern — download, execution, obfuscation, LOLBAS TTPs",
            "Indicator — payload URLs, file hashes, process names",
            "ConfidenceAnnotatedRelationship — Malware downloads Malware (staged)",
        ],
        "deprioritize": "Encryption-related objects (dropper does not encrypt user data)",
        "technique_focus": "T1105 (Ingress Tool Transfer), T1218 (Signed Binary Proxy Execution), "
                           "T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode)",
        "narrative": "Focus on download mechanism, payload staging, obfuscation technique, "
                     "and execution chain from dropper to final payload.",
    },
    MalwareCategory.WORM: {
        "focus_types": [
            "Malware — the worm",
            "AttackPattern — propagation, lateral movement, share enumeration TTPs",
            "Indicator — file copies, autorun entries, network scan signatures",
            "ConfidenceAnnotatedRelationship — Malware uses AttackPattern for propagation",
        ],
        "deprioritize": "Credential-specific objects unless credential-stealing worm",
        "technique_focus": "T1021 (Remote Services), T1091 (Removable Media Replication), "
                           "T1080 (Taint Shared Content), T1570 (Lateral Tool Transfer)",
        "narrative": "Focus on propagation mechanism, target selection, "
                     "self-copy logic, and network/removable media spread vectors.",
    },
    MalwareCategory.INFOSTEALER: {
        "focus_types": [
            "Malware — the infostealer",
            "AttackPattern — credential access, input capture, exfiltration TTPs",
            "Indicator — targeted browser paths, registry keys, exfil endpoints",
            "ConfidenceAnnotatedRelationship — Malware uses AttackPattern for theft",
        ],
        "deprioritize": "Ransomware-specific objects (encryption, ransom demands)",
        "technique_focus": "T1003 (OS Credential Dumping), T1056 (Input Capture), "
                           "T1555 (Credentials from Password Stores), T1041 (Exfiltration over C2)",
        "narrative": "Focus on targeted data types (credentials, PII, crypto wallets), "
                     "collection method, staging location, and exfiltration channel.",
    },
    MalwareCategory.UNKNOWN: {
        "focus_types": [],      # Empty → no pruning
        "deprioritize": "",
        "technique_focus": "",
        "narrative": "",
    },
}


# ---------------------------------------------------------------------------
# Inference engine
# ---------------------------------------------------------------------------

def _collect_text(
    reports: dict[str, str],
    isr_reports: dict[str, AgentISR] | None,
) -> str:
    """Collect and concatenate all available analysis text for keyword scanning."""
    parts: list[str] = list(reports.values())

    if isr_reports:
        for isr in isr_reports.values():
            for claim in isr.claims:
                parts.append(claim.claim)
                parts.append(claim.evidence_ref)
                if claim.technique_id:
                    parts.append(claim.technique_id)

    return " ".join(parts).lower()


def infer_malware_category(
    reports: dict[str, str],
    isr_reports: dict[str, AgentISR] | None = None,
) -> MalwareCategory:
    """Infer malware behavioral category from expert reports and ISR claims.

    Uses weighted keyword scoring against the combined text of all analyst
    reports and ISR claim/technique_id fields. The category with the highest
    cumulative score wins. Ties or all-zero scores return UNKNOWN.

    This is intentionally a lightweight heuristic — the goal is a rough
    directional signal for STIX schema pruning, not a precise classifier.

    Args:
        reports:     Mapping of agent name to report text.
        isr_reports: Optional structured ISR objects for richer signal.

    Returns:
        The inferred MalwareCategory (UNKNOWN if no clear signal).
    """
    if not reports and not isr_reports:
        return MalwareCategory.UNKNOWN

    text = _collect_text(reports, isr_reports)
    if not text.strip():
        return MalwareCategory.UNKNOWN

    scores: dict[MalwareCategory, float] = {
        cat: 0.0 for cat in MalwareCategory if cat is not MalwareCategory.UNKNOWN
    }

    for category, keywords in _CATEGORY_KEYWORDS.items():
        for keyword, weight in keywords:
            if keyword in text:
                scores[category] += weight

    best_category = max(scores, key=lambda c: scores[c])
    best_score = scores[best_category]

    if best_score == 0.0:
        return MalwareCategory.UNKNOWN

    # Check for tie: if second-best has same score, return UNKNOWN (ambiguous)
    sorted_scores = sorted(scores.values(), reverse=True)
    if len(sorted_scores) >= 2 and sorted_scores[0] == sorted_scores[1]:  # noqa: PLR2004
        return MalwareCategory.UNKNOWN

    return best_category


def get_pruned_schema_hint(category: MalwareCategory) -> str:
    """Build a prompt-ready STIX object type recommendation block.

    For UNKNOWN category, returns an empty string (no pruning applied).
    For all other categories, returns a block guiding the LLM to focus
    on the most relevant STIX object types and ATT&CK techniques.

    Args:
        category: Inferred malware category.

    Returns:
        A formatted string block suitable for injection into the judge
        system prompt, or empty string for UNKNOWN / no pruning.
    """
    if category is MalwareCategory.UNKNOWN:
        return ""

    hints = _CATEGORY_HINTS[category]
    focus_types = hints["focus_types"]
    deprioritize = hints["deprioritize"]
    technique_focus = hints["technique_focus"]
    narrative = hints["narrative"]

    if not focus_types:
        return ""

    lines = [
        f"INFERRED MALWARE CATEGORY: {category.value.upper()}",
        "",
        "STIX OBJECT TYPE GUIDANCE (schema pruning):",
        "Focus on producing these object types for this malware category:",
    ]
    for ft in focus_types:
        lines.append(f"  - {ft}")

    if deprioritize:
        lines.append(f"\nDEPRIORITIZE: {deprioritize}")

    if technique_focus:
        lines.append("\nKEY MITRE ATT&CK TECHNIQUES for this category:")
        lines.append(f"  {technique_focus}")

    if narrative:
        lines.append(f"\nNARRATIVE FOCUS: {narrative}")

    return "\n".join(lines)
