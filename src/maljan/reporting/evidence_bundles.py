"""Per-section evidence bundles — the Composer's anti-hallucination boundary.

The section-wise Report Composer authors one report section per LLM
call. Each call must see ONLY the evidence relevant to its section, so it can
cite real artifacts and cannot borrow (or invent) content from another section.
``bundle_for(section, ...)`` assembles that tight slice from three sources:

  - ISR claims (``report`` deterministic fields + ``isr_reports``),
  - captured tool outputs (``technical_evidence``),
  - deterministic facts already on the report.

A bundle is a plain dict of strings/lists ready to drop into a prompt. When a
bundle is empty the Composer must state the section's absence explicitly rather
than fabricate — see other/docs/report-reference/ ("state absence explicitly").
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.models import MalwareReport

# Section keys the Composer authors. Kept as plain strings (not an enum) so the
# Composer can iterate a config-driven subset per malware type.
SECTIONS = (
    "executive_summary",
    "introduction",
    "execution_flow",
    "packing_obfuscation",
    "string_resolution",
    "configuration",
    "commands",
    "cli_flags",
    "encryption_scheme",
    "discovery",
    "persistence_detail",
    "evasion_antiforensics",
    "command_and_control",
    "payloads",
    "ransom_note",
    "communications",
    "mitigations",
)

# The ledger tools a sandbox answers through. An execution step the report
# model marks ``observed`` has to cite one of their entries.
SANDBOX_TOOL_PREFIXES = ("sandbox_", "pcap_summary")

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
    "command_and_control": (
        "list_strings",
        "extract_iocs_with_context",
        "analyze_api_call_chains",
        "decompile_function",
    ),
    "string_resolution": (
        "emulate_hash_batch",
        "emulate_function",
        "analyze_api_call_chains",
        "decompile_function",
        "list_strings",
    ),
    "configuration": (
        "emulate_function",
        "emulate_hash_batch",
        "analyze_dataflow",
        "detect_crypto_constants",
        "extract_iocs_with_context",
        "decompile_function",
    ),
    "commands": ("decompile_function", "analyze_function_complete", "analyze_api_call_chains"),
    "payloads": ("list_segments", "decompile_function", "extract_iocs_with_context"),
    "host_identifiers": ("list_strings", "extract_iocs_with_context"),
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
    "command_and_control": (
        "c2",
        "command and control",
        "beacon",
        "exfil",
        "network",
        "http",
        "connect",
        "user-agent",
        "user agent",
    ),
    "string_resolution": (
        "hash",
        "resolve",
        "peb",
        "getprocaddress",
        "loadlibrary",
        "decrypt",
        "string",
        "import",
    ),
    "configuration": (
        "config",
        "campaign",
        "group",
        "key",
        "version",
        "sleep",
        "interval",
        "c2",
        "domain",
        "url",
        "rc4",
        "xor",
        "decrypt",
    ),
    "commands": ("command", "handler", "opcode", "instruction", "dispatch", "switch", "task id"),
    # Generic category words, never a sample's values, and never shown to a
    # model: they pick which analyst claims reach the section's bundle. The
    # prompt-leak test reads what a model is shown, so it does not read this.
    "host_identifiers": (
        "mutex",
        "path",
        "folder",
        "directory",
        "registry",
        "file name",
        "task",
        "pipe",
        "service",
        "user agent",
        "user-agent",
        "marker",
    ),
    "payloads": ("payload", "drop", "carve", "embedded", "stage", "download", "inject", "overlay"),
}


def _claims_text(report: MalwareReport, isr_reports: dict[str, Any] | None) -> list[dict[str, str]]:
    """Every claim in force as ``{claim, evidence_ref, agent, label}``, in the answers' order.

    ``label`` names the claim by its analyst and its number in the answer in
    force (``claim_coverage.claim_label``): the name the coverage check reads
    a citation of the claim by, and the one the report lists it under when the
    body neither cites nor discusses it.
    """
    from maljan.reporting.claim_coverage import claims_in_force

    return [
        {
            "claim": claim.claim,
            "evidence_ref": claim.evidence_ref,
            "agent": claim.agent,
            "label": claim.label,
        }
        for claim in claims_in_force(isr_reports)
    ]


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
                        # Whole: the composer shares the section's window
                        # among the answers it shows (``ReportComposer._item_chars``).
                        "output": str(o.get("output") or ""),
                    }
                )
    return picked


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
        # The list is shown whole, so it is always complete: no count cuts a
        # fact the section is grounded in, and the composer accounts for the
        # window it takes (``ReportComposer._room_chars``).
        facts[f"imported_dlls (complete list, {len(ordered)} total)"] = ordered
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
            "claims": all_claims,
            "tool_outputs": [],
            "binary": base,
            "facts": {
                "verdict": report.verdict,
                "confidence": (
                    None
                    if report.overall_confidence is None
                    else round(report.overall_confidence, 2)
                ),
                "category": report.malware_category,
                "severity": report.severity.rating if report.severity else None,
                "top_ttps": [f"{m.technique_id} {m.technique_name}" for m in report.ttp_mappings],
            },
        }
    if section == "introduction":
        return {
            "claims": all_claims,
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
    if section == "execution_flow":
        dynamic = report.dynamic
        sandbox_ids = set(sandbox_entry_ids(report))
        tree: list[str] = []
        for root in dynamic.process_tree if dynamic else []:
            tree.extend(_process_lines(root, 0))
        return {
            "claims": all_claims,
            "tool_outputs": [],
            "binary": base,
            "facts": {
                "process_tree": tree,
                "sandbox_entries": [
                    f"{row.id} ({row.tool})"
                    for row in report.evidence_index
                    if row.id in sandbox_ids
                ],
                "exports": list(report.static.exports) if report.static else [],
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
    if section in ("communications", "command_and_control"):
        net = report.network
        return {
            "claims": _filter_claims(all_claims, _SECTION_CLAIM_KEYWORDS[section]),
            "tool_outputs": _filter_tool_outputs(tech_ev, _SECTION_TOOL_HINTS[section]),
            "binary": base,
            "facts": {
                "domains": [d.fqdn for d in (net.domains if net else [])],
                "ips": [f"{i.address}:{i.port}" for i in (net.ips if net else [])],
                "urls": [u.url for u in (net.urls if net else [])],
                "user_agents": (net.user_agents if net else []),
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


def sandbox_entry_ids(report: MalwareReport) -> list[str]:
    """The ledger ids of the sandbox answers that recorded something, in issue order.

    A sandbox answer with nothing in it — a mock with no fixture, a call that
    returned empty lists — is not an observation, so a step citing only such
    an entry has not been observed. An answer recorded something when the
    section built from it holds a value: the section builders credit an entry
    only when it added a row, and the generic block's rows are read for a
    value that is not empty.
    """
    # The pack's sandbox-status entry states what the sandbox report is; it
    # records no behaviour and is never an observation to cite.
    sandbox = {
        row.id
        for row in report.evidence_index
        if str(row.tool or "").startswith(SANDBOX_TOOL_PREFIXES) and row.tool != "sandbox_status"
    }
    holding: set[str] = set()
    for section in report.sections:
        cited = sandbox.intersection(section.evidence_ids)
        if cited and section_holds_something(section):
            holding.update(cited)
    return [row.id for row in report.evidence_index if row.id in holding]


_EMPTY_VALUES = frozenset({"", "[]", "{}", "0", "none", "null", "-", "false", "no"})


def section_holds_something(section: Any) -> bool:
    """Whether an evidence section carries a value rather than an empty answer."""
    values: list[str] = []
    for row in getattr(section, "rows", None) or []:
        cells = [str(cell) for cell in row]
        # A key/value block's first cell is the field's name, not a value.
        values.extend(cells[1:] if getattr(section, "kind", "") == "kv" else cells)
    values.extend(str(item) for item in getattr(section, "items", None) or [])
    values.append(str(getattr(section, "text", "") or ""))
    return any(value.strip().lower() not in _EMPTY_VALUES for value in values)


def _process_lines(node: Any, depth: int) -> list[str]:
    """One line per process: pid, name and command line, children indented."""
    line = f"{'  ' * depth}pid {node.pid} {node.name}".rstrip()
    if node.command_line:
        line += f": {node.command_line}"
    out = [line]
    for child in node.children:
        out.extend(_process_lines(child, depth + 1))
    return out


# The tools whose answers are the sample's own strings, read or decoded.
_STRING_TOOLS = frozenset({"strings", "floss", "iocs_from_file", "list_strings"})

# The string-sweep kinds a responder searches a host for.
_HOST_STRING_KINDS = frozenset({"path", "registry", "mutex", "command"})


def _string_entries(report: MalwareReport) -> list[str]:
    """``ev_0012 (floss)`` for every answered entry whose output is the sample's strings."""
    return [
        f"{row.id} ({row.tool})"
        for row in report.evidence_index
        if str(row.tool or "") in _STRING_TOOLS and row.ok
    ]


def _technical_facts(section: str, report: MalwareReport) -> dict[str, Any]:
    """Deterministic measurements for one technical-spine section.

    Only what the section is actually about — the shared ``binary_facts`` block
    already carries identity, and a bundle that grows past roughly a thousand
    tokens is the long-prompt regime the per-section design exists to avoid.
    """
    if section == "payloads":
        return _payload_facts(report)
    if section == "configuration":
        net = report.network
        return {
            "urls": [u.url for u in (net.urls if net else [])],
            "domains": [d.fqdn for d in (net.domains if net else [])],
            "user_agents": (net.user_agents if net else []),
            "string_entries": _string_entries(report),
        }
    if section == "host_identifiers":
        static = report.static
        return {
            # The entries whose answers are the sample's own strings. The
            # strings themselves are in those entries and in the triage pack
            # every section leads with; the section reads them there and
            # decides what a responder should search for.
            "string_entries": _string_entries(report),
            "host_kind_strings": [
                f"{row.kind}: {row.value}"
                for row in (static.interesting_strings if static else [])
                if row.kind in _HOST_STRING_KINDS
            ],
        }
    if section == "commands":
        # Nothing measured says what an operator can ask for; the section runs
        # only when an analyst claim or a captured tool output speaks to it.
        return {}

    static = report.static
    if static is None:
        return {}

    caps = static.api_capabilities or {}
    # Distinct ids, in first-seen order. A row is a rule and two rules can
    # name one technique by two mechanisms, so a plain list handed the
    # narrative the same id twice and read as two findings.
    techniques = list(
        dict.fromkeys(
            str(h.get("technique_id"))
            for h in (static.api_technique_hits or [])
            if h.get("technique_id")
        )
    )

    if section == "packing_obfuscation":
        facts: dict[str, Any] = {
            "obfuscation_indicators": list(static.obfuscation_indicators),
            "high_entropy_sections": [
                f"{s.name} ({s.entropy:.2f})" for s in static.sections if s.entropy > 7.0
            ],
        }
        if static.packer_matches:
            facts["packer_matches"] = [_packer_line(m) for m in static.packer_matches]
        elif static.packer_hint:
            facts["packer_hint"] = static.packer_hint
        else:
            # Stated rather than omitted: "no packer was identified" is a
            # finding, and an absent key reads as "not measured".
            facts["packer_detected"] = False
        return facts

    # The counts below are the capability profile: capa's namespaces on the
    # ledger path, and on the extractor path the parked import-category table,
    # aggregated. The per-import lists that sat beside them were that table
    # read back one import at a time, and they are gone.
    if section == "encryption_scheme":
        return {"crypto_api_count": caps.get("crypto", 0)}
    if section == "discovery":
        return {
            "discovery_api_count": caps.get("discovery", 0),
            "discovery_techniques": [t for t in techniques if t in _DISCOVERY_TECHNIQUES],
        }
    if section == "evasion_antiforensics":
        return {
            "anti_debug_api_count": caps.get("anti_debug", 0),
            "evasion_api_count": caps.get("evasion", 0),
            "evasion_techniques": [t for t in techniques if t in _EVASION_TECHNIQUES],
        }
    if section == "persistence_detail":
        return {
            "persistence_mechanisms": [p.kind for p in report.persistence],
            "persistence_api_count": caps.get("persistence", 0),
            "registry_api_count": caps.get("registry", 0),
        }
    if section == "cli_flags":
        return {"capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1]))}
    if section == "string_resolution":
        return {
            "static_import_count": len(static.imports),
            "interesting_string_count": len(static.interesting_strings),
            "capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1])),
        }
    return {"capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1]))}


# Technique IDs the import-derived ATT&CK table can emit for these two
# subjects. Kept explicit rather than prefix-matched: T1497 is sandbox evasion
# and T1496 is resource hijacking, and a prefix rule would confuse them. A
# superset on purpose: capa emits its own ids into the same table, and a report
# stored before a rule was retired still has to bucket its rows.
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
        # T1685 is what ATT&CK 19.2 made of T1562.001 and T1562.006; the two
        # retired ids stay so a report written before the move still renders.
        "T1685",
        "T1562.001",
        "T1562.006",
        "T1070.004",
        "T1070.006",
        "T1564.003",
    }
)


def _packer_line(match: dict[str, Any]) -> str:
    """A packer match as the tool stated it: a confidence only when it gave one."""
    confidence = match.get("confidence")
    if not isinstance(confidence, int | float):
        return f"{match.get('name')} ({match.get('method')})"
    return f"{match.get('name')} ({float(confidence):.2f}, {match.get('method')})"


def _payload_facts(report: MalwareReport) -> dict[str, Any]:
    """The carved payloads and the dropped files, as the tools stated them."""
    carved = [
        f"{res.get('id')} ({res.get('type') or '?'}, {res.get('size', 0)} bytes, "
        f"sha256 {str(res.get('sha256') or '')})"
        for res in (report.static.embedded_resources if report.static else [])
        if res.get("carved")
    ]
    dropped = [
        str(op.get("path") or op.get("name") or "")
        for op in (report.dynamic.file_operations if report.dynamic else [])
        if isinstance(op, dict) and op.get("operation") == "write"
    ]
    return {"carved_payloads": carved, "dropped_files": [d for d in dropped if d]}


def is_empty(bundle: dict[str, Any]) -> bool:
    """A bundle with no claims, no tool outputs, and no meaningful facts."""
    if bundle.get("claims") or bundle.get("tool_outputs"):
        return False
    facts = bundle.get("facts") or {}
    return not any(v for v in facts.values())
