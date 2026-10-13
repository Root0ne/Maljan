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

import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any
from urllib.parse import urlsplit

from maljan.analysis.sandbox_sections import ItemIndex
from maljan.reporting import tool_kinds
from maljan.reporting.dedupe import distinct_processes
from maljan.reporting.models import MalwareReport
from maljan.schemas.sandbox_report import SAMPLE_TREE_KEY, section_id

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

# The ledger tools a sandbox answers through, by their declared kinds
# (``CONSUMER_KINDS``). An execution step the report model marks ``observed``
# has to cite one of their entries.
_SANDBOX_TOOLS = "evidence_bundles.SANDBOX_TOOL_PREFIXES"

# The sandbox answers about the network: a flow table and a capture. Either
# holds the guest's traffic as well as the sample's, so it shows a step was
# observed only when the sandbox attributed a flow to the sample's own tree.
_NETWORK_SANDBOX_TOOLS = "evidence_bundles._NETWORK_SANDBOX_TOOLS"

# The kinds of captured output each technical section is shown, so e.g. the
# encryption bundle never sees network tool output. A tool of one of these
# kinds reaches the section from any server; a tool may also name the sections
# it is shown to in its own declaration (``report_sections``). A function's
# code is shown as decompiled source or as its disassembly, whichever the
# reverser gives. A captured output with no recorded source is routed by its
# tool's name, as it always was (``legacy_tool_names.SECTION_TOOL_HINTS``).
_CODE = ("decompile", "function_disassembly")
_SECTION_KINDS: dict[str, tuple[str, ...]] = {
    "packing_obfuscation": ("segments", "anti_analysis_scan", "behaviour_scan"),
    "cli_flags": (*_CODE, "function_analysis", "documentation_completeness", "listing_strings"),
    "encryption_scheme": ("crypto_constants", "emulation", "dataflow"),
    "discovery": ("import_listing", "call_chains", *_CODE),
    "persistence_detail": ("listing_strings", *_CODE, "call_chains"),
    "evasion_antiforensics": ("anti_analysis_scan", "behaviour_scan", *_CODE),
    "ransom_note": ("listing_strings", "iocs_with_context"),
    "communications": ("listing_strings", "iocs_with_context", "call_chains"),
    "command_and_control": ("listing_strings", "iocs_with_context", "call_chains", *_CODE),
    "string_resolution": ("emulation", "call_chains", *_CODE, "listing_strings"),
    "configuration": ("emulation", "dataflow", "crypto_constants", "iocs_with_context", *_CODE),
    "commands": (*_CODE, "function_analysis", "documentation_completeness", "call_chains"),
    "payloads": ("segments", *_CODE, "iocs_with_context"),
    "host_identifiers": ("listing_strings", "iocs_with_context"),
}


def shown_to_section(section: str, output: dict[str, Any]) -> bool:
    """Whether one captured tool output belongs in a technical section's bundle.

    By the output's recorded source: its tool's declared kind is one the
    section reads, or its declaration names the section. A tool its source
    declares nothing for reaches the sections that read a function's code
    when its name says it lists one (``tool_kinds.undeclared_code_kind``), as
    the function map reads it. With no source, by the tool's name, as before.
    """
    by_name = tool_kinds.shown_by_name(section, output)
    if by_name is not None:
        return by_name
    facts = tool_kinds.facts_of(output)
    if facts is None:
        kind = tool_kinds.undeclared_code_kind(output)
        return kind in _CODE and kind in _SECTION_KINDS.get(section, ())
    return facts.kind in _SECTION_KINDS.get(section, ()) or section in facts.report_sections


# Keyword hints to pull the relevant ISR claims into a technical section.
_SECTION_CLAIM_KEYWORDS: dict[str, tuple[str, ...]] = {
    "packing_obfuscation": ("pack", "unpack", "obfuscat", "entropy", "encoded", "dynamic api"),
    "cli_flags": ("argument", "command-line", "command line", "flag", "parameter", "argv"),
    "encryption_scheme": (
        "encrypt",
        "aes",
        "rsa",
        "rc4",
        "xor",
        "crypto",
        "crypt",
        "cipher",
        "key",
    ),
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


def _word_starts(text: str) -> list[int]:
    """Where each word of ``text`` starts, in order.

    A word starts at a letter or digit that follows anything else, and inside
    a run of letters where the case says a new word begins: ``CryptEncrypt``
    is two words, ``HTTPRequest`` is ``HTTP`` and ``Request``. One pass.
    """
    starts: list[int] = []
    prev = ""
    for index, char in enumerate(text):
        if char.isalnum() and (
            not prev.isalnum()
            or (prev.islower() and char.isupper())
            or (
                prev.isupper()
                and char.isupper()
                and index + 1 < len(text)
                and text[index + 1].islower()
            )
        ):
            starts.append(index)
        prev = char
    return starts


# A keyword this long is a stem that names its subject inside a compound
# word too (``obfuscat`` in ``deobfuscation``, ``string`` in ``stackstrings``);
# a shorter one turns up inside unrelated words by chance (``rsa`` in
# ``rehearsal``, ``c2`` in ``0xc2c4``) and matches only where a word begins.
_STEM_LENGTH = 6


def mentions(text: str, keywords: tuple[str, ...]) -> bool:
    """Whether ``text`` holds one of ``keywords`` as a word or a word's prefix.

    A keyword shorter than ``_STEM_LENGTH`` matches where a word begins, as a
    whole word or its prefix (``rsa`` in ``RSA1`` and ``rsaenh``, ``key`` in
    ``KeyBlob``), never inside a word (``rsa`` in ``rehearsal``, ``key`` in
    ``monkey``, ``aes`` in ``caesar``); a longer one matches anywhere, as it
    always did. Case is ignored. Linear in the text for a given keyword list.
    """
    if not keywords:
        return False
    # Lowered one character at a time, so every index still names the same
    # character (a few characters lower to two).
    lowered = "".join(c.lower() if len(c.lower()) == 1 else c for c in text)
    stems = [k for k in keywords if len(k) >= _STEM_LENGTH]
    if any(k in lowered for k in stems):
        return True
    short = tuple(k for k in keywords if len(k) < _STEM_LENGTH)
    return bool(short) and any(lowered.startswith(short, at) for at in _word_starts(text))


def _filter_claims(claims: list[dict[str, str]], keywords: tuple[str, ...]) -> list[dict[str, str]]:
    if not keywords:
        return []
    return [c for c in claims if mentions(f"{c['claim']} {c['evidence_ref']}", keywords)]


def cited_entry_ids(claims: list[dict[str, str]]) -> set[str]:
    """The ledger entry ids the claims cite, in their text or their evidence."""
    from maljan.schemas.evidence import entry_ids_in

    cited: set[str] = set()
    for claim in claims:
        cited |= entry_ids_in(f"{claim.get('claim', '')} {claim.get('evidence_ref', '')}")
    return cited


def cited_undeclared_output(
    output: dict[str, Any], cited: set[str], index: dict[str, Any] | None
) -> bool:
    """Whether a captured output of a tool its source declares nothing for is cited.

    The analysts' citation decides where such an output goes: a section whose
    claims cite its entry is shown it, as a section is shown a declared kind
    it reads. Routing only. The output's entry is the job-wide call number
    the capture carries (``LedgerEntry.to_captured``), and it is held to the
    report's evidence index: the indexed entry must name the same tool and
    agent, or the output is not routed. A declared tool, and an output with no
    recorded source, are routed by :func:`shown_to_section` alone.
    """
    if not cited or index is None:
        return False
    if tool_kinds.source_of(output) is None or tool_kinds.facts_of(output) is not None:
        return False
    from maljan.schemas.evidence import format_entry_id

    seq = output.get("seq")
    # An output that carries no call number names no entry.
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return False
    entry_id = format_entry_id(seq + 1)
    row = index.get(entry_id)
    if entry_id not in cited or row is None:
        return False
    return str(getattr(row, "tool", "")) == str(output.get("tool_name") or "") and str(
        getattr(row, "agent", "")
    ) == str(output.get("agent_id") or "")


def _filter_tool_outputs(
    technical_evidence: dict[str, list[dict[str, Any]]] | None,
    section: str,
    cited: set[str] | None = None,
    index: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    if not technical_evidence:
        return []
    picked: list[dict[str, str]] = []
    for outputs in technical_evidence.values():
        for o in outputs or []:
            name = str(o.get("tool_name", ""))
            if shown_to_section(section, o) or cited_undeclared_output(o, cited or set(), index):
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

    Keys: ``claims`` (relevant ISR claims), ``tool_outputs`` (the captured tool
    outputs of the kinds the section reads, from any server:
    :func:`shown_to_section`; and the output of a tool its source declares
    nothing for when a claim of the section cites its entry:
    :func:`cited_undeclared_output`), ``facts`` (deterministic report data for the
    section), and ``binary`` (what the file demonstrably is — see
    :func:`binary_facts`).

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
        for root in distinct_processes(dynamic.process_tree if dynamic else []):
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
                "persistence_assessed": _assessed_persistence(report),
                "has_network": bool(
                    report.network and (report.network.domains or report.network.ips)
                ),
            },
        }
    if section in ("communications", "command_and_control"):
        net = report.network
        claims = _filter_claims(all_claims, _SECTION_CLAIM_KEYWORDS[section])
        return {
            "claims": claims,
            "tool_outputs": _filter_tool_outputs(
                tech_ev, section, cited_entry_ids(claims), _index_of(report)
            ),
            "binary": base,
            "facts": {
                "domains": [d.fqdn for d in (net.domains if net else [])],
                "ips": [f"{i.address}:{i.port}" for i in (net.ips if net else [])],
                "urls": [u.url for u in (net.urls if net else [])],
                "user_agents": (net.user_agents if net else []),
                "entries_holding": _network_holders(report),
            },
        }

    # Generic technical-spine section. These carried ``facts: {}`` until
    # 2026-07-28 — every one of them wrote prose about a subject the report had
    # already measured deterministically, without being shown the measurement.
    # A section describing packing that cannot see ``packer_matches`` has only
    # analyst claims to go on, and that is the same failure mode as the
    # conclusion's.
    claims = _filter_claims(all_claims, _SECTION_CLAIM_KEYWORDS.get(section, ()))
    return {
        "claims": claims,
        "tool_outputs": _filter_tool_outputs(
            tech_ev, section, cited_entry_ids(claims), _index_of(report)
        ),
        "binary": base,
        "facts": _technical_facts(section, report),
    }


def _index_of(report: MalwareReport) -> dict[str, Any]:
    """The report's evidence index by entry id."""
    return {row.id: row for row in report.evidence_index}


def _assessed_persistence(report: MalwareReport) -> list[str]:
    """The persistence the analysts listed, one line each, apart from the tools' mechanisms."""
    from maljan.reporting.ledger_report import analyst_persistence

    return [
        " ".join(
            part
            for part in (
                row["kind"],
                row["target"],
                f"-> {row['payload']}" if row["payload"] else "",
                f"(listed by the {row['listed_by']} analyst)" if row["listed_by"] else "",
            )
            if part
        )
        for row in analyst_persistence(report.sections)
    ]


def sandbox_watched_persistence(report: MalwareReport) -> bool:
    """Whether a sandbox report is held whose registry and file views were not unavailable."""
    dyn = report.dynamic
    blind = {section_id(name) for name in (dyn.unavailable if dyn else [])}
    return dyn is not None and not blind.intersection(
        {"registry", "files", "file", "file_operations", "filesystem"}
    )


def sandbox_saw_no_persistence(report: MalwareReport) -> bool:
    """The fact the Persistence section prints as "no persistence observed".

    The sandbox watched the registry and the files, and no persistence row
    was recorded.
    """
    return not report.persistence and sandbox_watched_persistence(report)


def sandbox_entry_ids(report: MalwareReport) -> list[str]:
    """The ledger ids of the sandbox answers that recorded something, in issue order.

    A sandbox answer with nothing in it — a mock with no fixture, a call that
    returned empty lists — is not an observation, so a step citing only such
    an entry has not been observed. An answer recorded something when the
    section built from it holds a value: the section builders credit an entry
    only when it added a row, and the generic block's rows are read for a
    value that is not empty.

    A network answer — the flow table, the capture — is an observation of the
    sample only when the report's network block holds a sandbox row the
    sandbox attributed to the sample's process tree: without one, what it
    recorded is the guest's traffic, and a step citing it was not observed.
    Process, file and registry answers are the sample's by what they record.
    """
    sample_flow = _sample_tree_made_a_flow(report)
    # The pack's sandbox-status entry states what the sandbox report is, and
    # its section index how many items each section holds; neither records
    # behaviour, and neither is an observation to cite.
    rows = {
        row.id: row
        for row in report.evidence_index
        if tool_kinds.is_of(row, _SANDBOX_TOOLS) and not _states_the_report(row)
    }
    holding: set[str] = set()
    for section in report.sections:
        cited = set(rows).intersection(section.evidence_ids)
        if not cited or not section_holds_something(section):
            continue
        if not sample_flow:
            cited = {eid for eid in cited if not _answers_about_the_network(rows[eid], section)}
        holding.update(cited)
    return [row.id for row in report.evidence_index if row.id in holding]


# The kinds of the sandbox entries that state what the report is or holds, not what it saw.
_REPORT_STATE_KINDS = frozenset({"sandbox_status", "sandbox_sections"})


def _states_the_report(row: Any) -> bool:
    """Whether a sandbox entry states what the report is or holds (by its kind)."""
    return tool_kinds.kind_of(row) in _REPORT_STATE_KINDS


def sandbox_item_observation(
    report: MalwareReport, items: ItemIndex | None
) -> Callable[[str], bool] | None:
    """Whether a sandbox item id a step marked observed cites is an observation, or ``None``.

    ``items`` is the run's section index. An item is one row the sandbox
    recorded, so it is an observation as the answer holding it is: a network
    item only when the sandbox attributed a flow to the sample's own tree, by
    the rule :func:`sandbox_entry_ids` applies to the network answers, unless
    the item's own row states its attribution (``sample_process_tree``), which
    then decides it. One lookup per cited id; no id list is built.
    """
    if items is None or not items.holds_items:
        return None
    sample_flow = _sample_tree_made_a_flow(report)
    read_item = getattr(items, "item", None)

    def observed(value: str) -> bool:
        text = str(value).strip().lower()
        if not items.known(text):
            return False
        if not text.startswith("net:"):
            return True
        # A row that states its own attribution is read by it; else the run's rule.
        found = read_item(text) if callable(read_item) else None
        fields = found.get("fields") if isinstance(found, dict) else None
        stated = fields.get(SAMPLE_TREE_KEY) if isinstance(fields, dict) else None
        return stated if isinstance(stated, bool) else sample_flow

    return observed


# The named sections of a sandbox report that record traffic, as the section
# built from a ``sandbox_report_section`` answer is keyed (``sandbox_<name>``).
_NETWORK_REPORT_SECTIONS = frozenset(
    {"network", "dns", "http", "https", "tcp", "udp", "tls", "hosts", "domains", "pcap"}
)


def _answers_about_the_network(row: Any, section: Any) -> bool:
    """Whether a sandbox answer records traffic: the flow table, the capture, a network section."""
    if tool_kinds.is_of(row, _NETWORK_SANDBOX_TOOLS):
        return True
    name = str(getattr(section, "key", "") or "").removeprefix("sandbox_").lower()
    if tool_kinds.is_kind(row, "sandbox_items"):
        return name == "items_network"
    return tool_kinds.is_kind(row, "sandbox_report_section") and name in _NETWORK_REPORT_SECTIONS


def sample_flow_fact(report: MalwareReport) -> Any:
    """``(kind, value) -> reason``: why the sandbox shows no flow of the sample to a value.

    ``""`` when a flow to it came from the sample's process tree: an address
    the tree reached, a name that resolved to one, a URL on either. Otherwise
    the sandbox's own fact about the value, in the publish rule's words for a
    row it recorded (``stix_renderer.sandbox_row_kwargs``), or that it
    recorded no flow to it. A platform fact read from the network block,
    right or absent; what a step marked observed is asked against.
    """
    from maljan.reporting.ledger_projection import value_key
    from maljan.reporting.renderers.stix_renderer import sandbox_row_kwargs, url_host

    network = report.network
    ips = {value_key("ip", ip.address): ip for ip in (network.ips if network else [])}
    names = {
        value_key("domain", domain.fqdn): domain for domain in (network.domains if network else [])
    }
    reached = {key for key, ip in ips.items() if ip.sample_process_tree is True}

    def _address(value: str) -> str:
        key = value_key("ip", value)
        if key in reached:
            return ""
        row = ips.get(key)
        if row is not None and row.source == "sandbox":
            said = sandbox_row_kwargs(report, "ip", value).get("unattributed")
            if said:
                return str(said)
        return "the sandbox records no flow of the sample's process tree to it"

    def _name(value: str) -> str:
        row = names.get(value_key("domain", value))
        resolved = [str(a) for a in (row.resolved_ips if row is not None else [])]
        if any(value_key("ip", address) in reached for address in resolved):
            return ""
        if resolved:
            return (
                f"none of the addresses it resolved to ({', '.join(resolved)}) has a flow the "
                "sandbox attributes to the sample's process tree"
            )
        return "the sandbox records no address it resolved to that the sample's tree reached"

    def _fact(kind: str, value: str) -> str:
        text = str(value or "").strip()
        if kind == "url":
            text = url_host(text)
        text = text.strip("[]")
        if not text:
            return ""
        try:
            ipaddress.ip_address(text)
        except ValueError:
            return _name(text)
        return _address(text)

    return _fact


def _sample_tree_made_a_flow(report: MalwareReport) -> bool:
    """Whether the network block holds a sandbox row attributed to the sample's process tree."""
    network = report.network
    return network is not None and any(
        ip.source == "sandbox" and ip.sample_process_tree is True for ip in network.ips
    )


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


# The tools whose answers are the sample's own strings, read or decoded, by
# their declared kinds (``CONSUMER_KINDS``).
_STRING_TOOLS = "evidence_bundles._STRING_TOOLS"

# The string-sweep kinds a responder searches a host for.
_HOST_STRING_KINDS = frozenset({"path", "registry", "mutex", "command"})


# What ends a token when an answer's text is read for the values it holds.
_TOKEN_BREAK = re.compile(r"[\s\"'`<>()\[\]{},;|]+")


def _token_forms(token: str) -> Iterator[str]:
    """The values one token of an answer names: itself, trimmed, its host, its address."""
    trimmed = token.rstrip(".:/")
    yield token
    if trimmed != token:
        yield trimmed
    if "://" in trimmed:
        host = urlsplit(trimmed).hostname
        if host:
            yield host
    address, sep, port = trimmed.rpartition(":")
    if sep and port.isdigit() and address.count(".") == 3:
        yield address


def _value_holders(report: MalwareReport) -> dict[str, dict[str, None]]:
    """Every value the report's answered entries hold, each with the entries holding it.

    Read from two places, each naming the entry exactly: a captured tool
    output (its call number names its entry, held to the evidence index by
    tool, as :func:`cited_undeclared_output` holds it), and a report section
    built from one entry, or a table row that names its own entry. A section
    built from several entries whose rows name none is not read: which entry
    holds a value there is not known. Only entries the index files as
    answered count. One pass over the texts.
    """
    from maljan.schemas.evidence import entry_ids_in, format_entry_id

    index = _index_of(report)
    held: dict[str, dict[str, None]] = {}

    def add(text: str, entry_ids: Iterable[str]) -> None:
        ids = [i for i in entry_ids if (row := index.get(i)) is not None and row.ok]
        if not ids:
            return
        for token in _TOKEN_BREAK.split(text):
            for form in _token_forms(token) if token else ():
                holders = held.setdefault(form, {})
                holders.update(dict.fromkeys(ids))

    for outputs in (report.technical_evidence or {}).values():
        for output in outputs:
            seq = output.get("seq")
            if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
                continue
            entry_id = format_entry_id(seq + 1)
            row = index.get(entry_id)
            tool = str(output.get("tool_name") or output.get("tool") or "")
            if row is not None and str(getattr(row, "tool", "")) == tool:
                add(str(output.get("output") or ""), (entry_id,))
    for section in report.sections:
        if len(section.evidence_ids) == 1:
            cells = [cell for row in section.rows for cell in row]
            add("\n".join([*cells, *section.items, section.text]), section.evidence_ids)
            continue
        for row in section.rows:
            named = sorted(entry_ids_in(" ".join(row)) & set(section.evidence_ids))
            if named:
                add("\n".join(row), named)
    return held


def value_entries(report: MalwareReport, values: Iterable[str]) -> list[str]:
    """``<value>: ev_0006, ev_0030`` for each of ``values`` an answered entry holds, in order.

    A value no entry is known to hold is left out rather than given an entry
    that may not hold it. An ``address:port`` value is looked up by its
    address too.
    """
    values = [v for v in dict.fromkeys(values) if v]
    if not values:
        return []
    held = _value_holders(report)
    out: list[str] = []
    for value in values:
        address, _sep, port = value.rpartition(":")
        ids = held.get(value) or (held.get(address) if port.isdigit() or port == "None" else None)
        if ids:
            out.append(f"{value}: {', '.join(sorted(ids))}")
    return out


def _network_holders(report: MalwareReport) -> list[str]:
    """The entries holding each url, domain and ip of the report's network block."""
    net = report.network
    if net is None:
        return []
    return value_entries(
        report,
        [
            *(u.url for u in net.urls),
            *(d.fqdn for d in net.domains),
            *(f"{i.address}:{i.port}" for i in net.ips),
        ],
    )


def _string_entries(report: MalwareReport) -> list[str]:
    """``ev_0012 (floss)`` for every answered entry whose output is the sample's strings."""
    return [
        f"{row.id} ({row.tool})"
        for row in report.evidence_index
        if row.ok and tool_kinds.is_of(row, _STRING_TOOLS)
    ]


def _technical_facts(section: str, report: MalwareReport) -> dict[str, Any]:
    """Deterministic measurements for one technical-spine section.

    Only what the section is actually about — the shared ``binary_facts`` block
    already carries identity, and a bundle that grows past roughly a thousand
    tokens is the long-prompt regime the per-section design exists to avoid.
    """
    if section == "payloads":
        return _payload_facts(report)
    if section == "persistence_detail":
        # The tools' mechanisms and the analysts' listed rows, as two facts:
        # a run whose static block is empty still has both to state.
        profile = (report.static.api_capabilities or {}) if report.static else {}
        return {
            "persistence_mechanisms": [p.kind for p in report.persistence],
            "persistence_assessed": _assessed_persistence(report),
            "persistence_api_count": profile.get("persistence", 0),
            "registry_api_count": profile.get("registry", 0),
        }
    if section == "configuration":
        net = report.network
        return {
            "urls": [u.url for u in (net.urls if net else [])],
            "domains": [d.fqdn for d in (net.domains if net else [])],
            "user_agents": (net.user_agents if net else []),
            "string_entries": _string_entries(report),
            "entries_holding": _network_holders(report),
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
    if section == "cli_flags":
        return {"capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1]))}
    if section == "string_resolution":
        resolution: dict[str, Any] = {
            "static_import_count": len(static.imports),
            "interesting_string_count": len(static.interesting_strings),
            "capability_profile": dict(sorted(caps.items(), key=lambda kv: -kv[1])),
        }
        if static.api_capabilities_resolved:
            # The names the run resolved at runtime, apart from the imports:
            # the section is about how the sample finds them.
            resolution["capability_profile_of_names_resolved_at_runtime_not_imports"] = dict(
                sorted(static.api_capabilities_resolved.items(), key=lambda kv: -kv[1])
            )
        return resolution
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
