"""Per-section evidence bundles — the Composer's anti-hallucination boundary.

The section-wise Report Composer (Phase 4) authors one report section per LLM
call. Each call must see ONLY the evidence relevant to its section, so it can
cite real artifacts and cannot borrow (or invent) content from another section.
``bundle_for(section, ...)`` assembles that tight slice from three sources:

  - ISR claims (``report`` deterministic fields + ``isr_reports``),
  - captured tool outputs (``technical_evidence``, Phase 1),
  - deterministic facts already on the report.

A bundle is a plain dict of strings/lists ready to drop into a prompt. When a
bundle is empty the Composer must state the section's absence explicitly rather
than fabricate — see docs/report-reference/ ("state absence explicitly").
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.models import MalwareReport

# Section keys the Composer authors. Kept as plain strings (not an enum) so the
# Composer can iterate a config-driven subset per malware type (Phase 8).
SECTIONS = (
    "executive_summary",
    "introduction",
    "packing_obfuscation",
    "cli_flags",
    "encryption_scheme",
    "discovery",
    "persistence_detail",
    "evasion_antiforensics",
    "ransom_note",
    "communications",
    "conclusion",
    "mitigations",
)

# Tool names whose captured output is relevant to each technical section. Used
# to filter ``technical_evidence`` so e.g. the encryption bundle never sees
# network tool output.
_SECTION_TOOL_HINTS: dict[str, tuple[str, ...]] = {
    "packing_obfuscation": ("list_segments", "find_anti_analysis", "detect_malware_behaviors"),
    "cli_flags": ("decompile_function", "analyze_function_complete", "list_strings"),
    "encryption_scheme": (
        "detect_crypto_constants",
        "emulate_function",
        "emulate_hash_batch",
        "analyze_dataflow",
    ),
    "discovery": ("list_imports", "analyze_api_call_chains", "decompile_function"),
    "persistence_detail": ("list_strings", "decompile_function", "analyze_api_call_chains"),
    "evasion_antiforensics": (
        "find_anti_analysis_techniques",
        "detect_malware_behaviors",
        "decompile_function",
    ),
    "ransom_note": ("list_strings", "extract_iocs_with_context"),
    "communications": ("list_strings", "extract_iocs_with_context", "analyze_api_call_chains"),
}

# Keyword hints to pull the relevant ISR claims into a technical section.
_SECTION_CLAIM_KEYWORDS: dict[str, tuple[str, ...]] = {
    "packing_obfuscation": ("pack", "obfuscat", "entropy", "encoded", "dynamic api"),
    "cli_flags": ("argument", "command-line", "command line", "flag", "parameter", "argv"),
    "encryption_scheme": ("encrypt", "aes", "rsa", "rc4", "xor", "crypto", "cipher", "key"),
    "discovery": ("enumerate", "discovery", "drive", "registry query", "system info"),
    "persistence_detail": ("persist", "run key", "scheduled task", "startup", "service", "autorun"),
    "evasion_antiforensics": ("evasion", "anti-", "unhook", "masquerad", "syslog", "shadow"),
    "ransom_note": ("ransom", "note", "readme", "extortion"),
    "communications": (
        "c2",
        "command and control",
        "beacon",
        "exfil",
        "network",
        "http",
        "connect",
    ),
}


def _claims_text(report: MalwareReport, isr_reports: dict[str, Any] | None) -> list[dict[str, str]]:
    """Flatten every ISR claim into ``{claim, evidence_ref, agent}`` dicts."""
    out: list[dict[str, str]] = []
    for agent_id, isr in (isr_reports or {}).items():
        for c in getattr(isr, "claims", None) or []:
            out.append(
                {
                    "claim": str(getattr(c, "claim", "")),
                    "evidence_ref": str(getattr(c, "evidence_ref", "")),
                    "agent": str(agent_id),
                }
            )
    return out


def _filter_claims(claims: list[dict[str, str]], keywords: tuple[str, ...]) -> list[dict[str, str]]:
    if not keywords:
        return []
    picked = []
    for c in claims:
        hay = f"{c['claim']} {c['evidence_ref']}".lower()
        if any(k in hay for k in keywords):
            picked.append(c)
    return picked


def _filter_tool_outputs(
    technical_evidence: dict[str, list[dict[str, Any]]] | None, hints: tuple[str, ...]
) -> list[dict[str, str]]:
    if not technical_evidence or not hints:
        return []
    picked: list[dict[str, str]] = []
    for outputs in technical_evidence.values():
        for o in outputs or []:
            name = str(o.get("tool_name", ""))
            if any(h in name for h in hints):
                picked.append(
                    {
                        "tool": name,
                        "symbol": str(o.get("symbol") or ""),
                        "output": str(o.get("output") or "")[:2500],
                    }
                )
    return picked


def bundle_for(
    section: str,
    report: MalwareReport,
    technical_evidence: dict[str, list[dict[str, Any]]] | None = None,
    isr_reports: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the isolated evidence slice for ``section``.

    Keys: ``claims`` (relevant ISR claims), ``tool_outputs`` (relevant captured
    Ghidra output), ``facts`` (deterministic report data for the section). The
    Composer treats an empty bundle as "state absence explicitly".
    """
    all_claims = _claims_text(report, isr_reports)
    tech_ev = technical_evidence if technical_evidence is not None else report.technical_evidence

    if section == "executive_summary":
        return {
            "claims": all_claims[:12],
            "tool_outputs": [],
            "facts": {
                "verdict": report.verdict,
                "confidence": round(report.overall_confidence, 2),
                "category": report.malware_category,
                "severity": report.severity.rating,
                "top_ttps": [
                    f"{m.technique_id} {m.technique_name}" for m in report.ttp_mappings[:6]
                ],
            },
        }
    if section == "introduction":
        return {
            "claims": all_claims[:8],
            "tool_outputs": [],
            "facts": {
                "file_type": report.identity.file_type,
                "platform": report.identity.platform,
                "language_or_compiler": report.identity.language_or_compiler,
                "category": report.malware_category,
                "family": report.attribution.family if report.attribution else None,
            },
        }
    if section == "conclusion":
        return {
            "claims": all_claims[:10],
            "tool_outputs": [],
            "facts": {
                "verdict": report.verdict,
                "severity": report.severity.rating,
                "confidence": round(report.overall_confidence, 2),
                "degraded": report.degraded_mode,
            },
        }
    if section == "mitigations":
        return {
            "claims": all_claims,
            "tool_outputs": [],
            "facts": {
                "ttps": [f"{m.technique_id} {m.technique_name}" for m in report.ttp_mappings],
                "persistence": [p.kind for p in report.persistence],
                "has_network": bool(
                    report.network and (report.network.domains or report.network.ips)
                ),
            },
        }
    if section == "communications":
        net = report.network
        return {
            "claims": _filter_claims(all_claims, _SECTION_CLAIM_KEYWORDS["communications"]),
            "tool_outputs": _filter_tool_outputs(tech_ev, _SECTION_TOOL_HINTS["communications"]),
            "facts": {
                "domains": [d.fqdn for d in (net.domains if net else [])][:20],
                "ips": [f"{i.address}:{i.port}" for i in (net.ips if net else [])][:20],
                "urls": [u.url for u in (net.urls if net else [])][:20],
                "user_agents": (net.user_agents if net else [])[:5],
            },
        }

    # Generic technical-spine section: keyword-filtered claims + tool outputs.
    return {
        "claims": _filter_claims(all_claims, _SECTION_CLAIM_KEYWORDS.get(section, ())),
        "tool_outputs": _filter_tool_outputs(tech_ev, _SECTION_TOOL_HINTS.get(section, ())),
        "facts": {},
    }


def is_empty(bundle: dict[str, Any]) -> bool:
    """A bundle with no claims, no tool outputs, and no meaningful facts."""
    if bundle.get("claims") or bundle.get("tool_outputs"):
        return False
    facts = bundle.get("facts") or {}
    return not any(v for v in facts.values())
