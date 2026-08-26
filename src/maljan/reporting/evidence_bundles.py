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
than fabricate — see other/docs/report-reference/ ("state absence explicitly").
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


_MAX_DLLS = 24


def binary_facts(report: MalwareReport) -> dict[str, Any]:
    """What the binary demonstrably *is*, straight from the parsers.

    Every bundle carries this. The reason is a defect observed on 2026-07-28:
    the conclusion asserted the sample was a .NET executable calling
    ``_CorExeMain`` from ``mscoree.dll`` on a binary whose identity section read
    "Microsoft Visual C++ 2015-2022" and whose import table named eleven native
    DLLs and no ``mscoree`` at all.

    The claim came from the static analyst. The conclusion bundle passed that
    claim through and carried only verdict/severity/confidence/degraded as
    facts, so nothing in the prompt could contradict it — the section was
    grounded in claims, and claims are themselves LLM output. Bundle isolation
    is what keeps each call small enough for the local model to stay coherent;
    it must not also remove the evidence that falsifies a wrong claim.

    Kept deliberately small so it does not crowd out the section's own
    evidence: what the file is, what built it, whether it is signed, and the
    DLLs it actually imports.
    """
    identity = report.identity
    static = report.static
    dlls: list[str] = []
    if static is not None:
        seen: set[str] = set()
        for row in static.imports:
            name = (row.dll or "").lower()
            if name and name not in seen:
                seen.add(name)
                dlls.append(name)

    facts: dict[str, Any] = {
        "file_type": identity.file_type,
        "platform": identity.platform,
        "language_or_compiler": identity.language_or_compiler,
        "is_signed": identity.signing.is_signed,
    }
    if identity.signing.signer_subject:
        facts["signer"] = identity.signing.signer_subject
    if static is not None and static.pdb_path:
        # The linker's own build path. On the observed failure this named
        # BdUserHost — a native product — while the prose claimed .NET.
        facts["pdb_path"] = static.pdb_path
    if dlls:
        ordered = sorted(dlls)
        # Completeness is stated, and only when it is true. The first pass at
        # this shipped the list unqualified, and the model treated absence from
        # it as unproven: it kept a static-analyst claim that the binary loads
        # `mscoree.dll` while the list plainly did not contain it, and
        # reconciled the two into "a VC++ binary that is also a .NET wrapper".
        # A truncated list must NOT be called complete — that would trade one
        # wrong inference for a worse one.
        if len(ordered) <= _MAX_DLLS:
            facts[f"imported_dlls (complete list, {len(ordered)} total)"] = ordered
        else:
            facts[f"imported_dlls (first {_MAX_DLLS} of {len(ordered)}, NOT exhaustive)"] = ordered[
                :_MAX_DLLS
            ]
        # Stated as its own fact rather than left to be inferred from the list.
        # Deliberately named for what is actually measured: a binary that does
        # not import the CLR shim is not thereby proven managed-code-free, but
        # "does not import mscoree.dll" is exactly true and is what refutes the
        # specific claim that it calls `_CorExeMain` from it.
        facts["imports_dotnet_runtime (mscoree.dll)"] = "mscoree.dll" in dlls
    return facts


def bundle_for(
    section: str,
    report: MalwareReport,
    technical_evidence: dict[str, list[dict[str, Any]]] | None = None,
    isr_reports: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the isolated evidence slice for ``section``.

    Keys: ``claims`` (relevant ISR claims), ``tool_outputs`` (relevant captured
    Ghidra output), ``facts`` (deterministic report data for the section), and
    ``binary`` (what the file demonstrably is — see :func:`binary_facts`).

    ``binary`` is separate from ``facts`` on purpose. :func:`is_empty` keys off
    ``facts``, and it is what makes the Composer skip a section instead of
    inventing one; a block that is present on every bundle would make every
    bundle look non-empty and defeat that.
    """
    all_claims = _claims_text(report, isr_reports)
    tech_ev = technical_evidence if technical_evidence is not None else report.technical_evidence
    # Prepended to every section's facts, so no section can contradict what the
    # binary demonstrably is. See ``binary_facts``.
    base = binary_facts(report)

    if section == "executive_summary":
        return {
            "claims": all_claims[:12],
            "tool_outputs": [],
            "binary": base,
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
            "binary": base,
            # Identity stays in ``facts`` here, duplicating part of ``base``,
            # because it is this section's actual subject — not cross-cutting
            # context. ``is_empty`` ignores ``binary``, so moving these out
            # would make the introduction skip itself on any report with no
            # category and no family, which is most static-only runs.
            # ``_bundle_text`` drops the duplicate lines when it renders.
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
            "binary": base,
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
            "binary": base,
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
            "binary": base,
            "facts": {
                "domains": [d.fqdn for d in (net.domains if net else [])][:20],
                "ips": [f"{i.address}:{i.port}" for i in (net.ips if net else [])][:20],
                "urls": [u.url for u in (net.urls if net else [])][:20],
                "user_agents": (net.user_agents if net else [])[:5],
            },
        }

    # Generic technical-spine section. These carried ``facts: {}`` until
    # 2026-07-28 — every one of them wrote prose about a subject the report had
    # already measured deterministically, without being shown the measurement.
    # A section describing packing that cannot see ``packer_matches`` has only
    # analyst claims to go on, and that is the same failure mode as the
    # conclusion's.
    return {
        "claims": _filter_claims(all_claims, _SECTION_CLAIM_KEYWORDS.get(section, ())),
        "tool_outputs": _filter_tool_outputs(tech_ev, _SECTION_TOOL_HINTS.get(section, ())),
        "binary": base,
        "facts": _technical_facts(section, report),
    }


def _technical_facts(section: str, report: MalwareReport) -> dict[str, Any]:
    """Deterministic measurements for one technical-spine section.

    Only what the section is actually about — the shared ``binary_facts`` block
    already carries identity, and a bundle that grows past roughly a thousand
    tokens is the long-prompt regime the per-section design exists to avoid.
    """
    static = report.static
    if static is None:
        return {}

    caps = static.api_capabilities or {}
    techniques = [
        str(h.get("technique_id"))
        for h in (static.api_technique_hits or [])
        if h.get("technique_id")
    ]

    if section == "packing_obfuscation":
        facts: dict[str, Any] = {
            "obfuscation_indicators": list(static.obfuscation_indicators)[:8],
            "high_entropy_sections": [
                f"{s.name} ({s.entropy:.2f})" for s in static.sections if s.entropy > 7.0
            ][:8],
        }
        if static.packer_matches:
            facts["packer_matches"] = [
                f"{m.get('name')} ({float(m.get('confidence') or 0.0):.2f}, {m.get('method')})"
                for m in static.packer_matches[:5]
            ]
        elif static.packer_hint:
            facts["packer_hint"] = static.packer_hint
        else:
            # Stated rather than omitted: "no packer was identified" is a
            # finding, and an absent key reads as "not measured".
            facts["packer_detected"] = False
        return facts

    if section == "encryption_scheme":
        return {
            "crypto_api_count": caps.get("crypto", 0),
            "crypto_imports": [i.function for i in static.imports if i.category == "crypto"][:15],
        }
    if section == "discovery":
        return {
            "discovery_api_count": caps.get("discovery", 0),
            "discovery_imports": [i.function for i in static.imports if i.category == "discovery"][
                :15
            ],
            "discovery_techniques": [t for t in techniques if t in _DISCOVERY_TECHNIQUES],
        }
    if section == "evasion_antiforensics":
        return {
            "anti_debug_api_count": caps.get("anti_debug", 0),
            "evasion_api_count": caps.get("evasion", 0),
            "evasion_imports": [
                i.function for i in static.imports if i.category in {"anti_debug", "evasion"}
            ][:15],
            "evasion_techniques": [t for t in techniques if t in _EVASION_TECHNIQUES],
        }
    if section == "persistence_detail":
        return {
            "persistence_mechanisms": [p.kind for p in report.persistence][:10],
            "persistence_api_count": caps.get("persistence", 0),
            "registry_api_count": caps.get("registry", 0),
        }
    if section == "cli_flags":
        return {"capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1])[:8])}
    if section == "string_resolution":
        return {
            "interesting_string_count": len(static.interesting_strings),
            "capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1])[:8]),
        }
    return {"capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1])[:8])}


# Technique IDs the import-derived ATT&CK table can emit for these two
# subjects. Kept explicit rather than prefix-matched: T1497 is sandbox evasion
# and T1496 is resource hijacking, and a prefix rule would confuse them.
_DISCOVERY_TECHNIQUES = frozenset(
    {
        "T1057",
        "T1082",
        "T1083",
        "T1087",
        "T1010",
        "T1012",
        "T1016",
        "T1049",
        "T1007",
        "T1614",
        "T1033",
    }
)
_EVASION_TECHNIQUES = frozenset(
    {
        "T1497",
        "T1497.003",
        "T1622",
        "T1620",
        "T1027",
        "T1140",
        "T1562.001",
        "T1562.006",
        "T1070.004",
        "T1070.006",
        "T1564.003",
    }
)


def is_empty(bundle: dict[str, Any]) -> bool:
    """A bundle with no claims, no tool outputs, and no meaningful facts."""
    if bundle.get("claims") or bundle.get("tool_outputs"):
        return False
    facts = bundle.get("facts") or {}
    return not any(v for v in facts.values())
