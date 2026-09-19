"""Turn the evidence ledger into the report's sections.

Every section here is built from something a tool actually returned, and every
section says which ledger entries it was built from. That is the whole design:
a reader who doubts a row can name the call behind it, and a section that can
name no call is a bug the contract test fails on.

The module is a dispatch table, not a pipeline. A tool the table knows gets a
purpose-built section — a PE section table looks like a PE section table, a
capa result looks like a capability list. A tool the table does not know still
lands in the report through the generic fallbacks: a JSON object becomes a
key/value block, a JSON array of objects becomes a table with the union of
their keys as columns, and anything else becomes a capped text block. That is
what makes the report open to a tool server nobody has written yet — adding a
tool adds a section without touching this file.

Agents contribute two more shapes. ``artifacts`` are the tables an analyst
established itself, grouped by their ``kind``; ``findings`` are its conclusions,
collected into one table that carries the techniques and the ids each was drawn
from. Both cite ledger ids the analyst was shown, so the same rule holds.

Two of those tables say the same thing twice often enough to be worth folding:
an indicator two tools both recovered and a finding two analysts both reached.
``reporting.dedupe`` says what makes two of them one, and a fold only ever
grows the set-shaped cells — the ids and the agents — leaving every word and
every number the first occurrence carried exactly as it was written.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from maljan.agents.output_shortening import BOOKKEEPING_KEY, our_key_in
from maljan.analysis.technique_ids import sigma_technique_ids
from maljan.reporting.dedupe import (
    MergeTally,
    finding_fingerprint,
    indicator_fingerprint,
    merge_cell,
)
from maljan.reporting.models import EvidenceSection

if TYPE_CHECKING:
    from maljan.schemas.evidence import LedgerEntry
    from maljan.schemas.isr_models import AgentISR

# A text section never becomes the report. Anything longer than this is a tool
# output that wants reading in the evidence endpoint, not pasting into a
# document.
MAX_TEXT_CHARS = 4000

# How many rows one generated table may carry. A strings dump or a busy process
# list would otherwise turn a report into a log file.
MAX_ROWS = 200


class _Sections:
    """The sections being built, keyed so repeated calls merge rather than repeat.

    Two ``pe_info`` calls on the same sample are one section table with the
    rows deduplicated and both entry ids cited, not two identical tables. That
    is the behaviour a model retrying a tool produces, and a report that showed
    it twice would read as two findings.
    """

    def __init__(self, merges: MergeTally | None = None) -> None:
        self._by_key: dict[str, EvidenceSection] = {}
        self._order: list[str] = []
        self._seen: dict[str, set[tuple[str, ...]]] = {}
        # Where a merged row's index lives, per section, for the two kinds of
        # row whose identity is not the whole row: an indicator and a finding.
        self._merged: dict[str, dict[tuple[str, str], int]] = {}
        self.merges = merges if merges is not None else MergeTally()

    def get(
        self,
        key: str,
        title: str,
        kind: str,
        *,
        columns: list[str] | None = None,
        source: str = "",
    ) -> EvidenceSection:
        section = self._by_key.get(key)
        if section is None:
            section = EvidenceSection(
                key=key,
                title=title,
                kind=kind,  # type: ignore[arg-type]
                columns=list(columns or []),
                source=source,
            )
            self._by_key[key] = section
            self._order.append(key)
            self._seen[key] = set()
        return section

    def cite(self, section: EvidenceSection, entry_id: str) -> None:
        if entry_id and entry_id not in section.evidence_ids:
            section.evidence_ids.append(entry_id)

    def credit(self, section: EvidenceSection, entry: LedgerEntry) -> None:
        """Cite one entry and record which tool the section came from.

        First writer wins: two tools that both contribute to a merged section
        are both cited, and the section is named after the one that opened it
        rather than whichever happened to run last.

        An entry whose answer this system had to shorten says so here, under
        the section it filled: every builder ends by crediting, so the one
        sentence reaches a table a dedicated builder drew as surely as a
        generic one, and a reader is never shown a page of a list as if it
        were the list.
        """
        if not section.source:
            section.source = f"tool:{entry.tool}"
        self.cite(section, entry.id)
        note_if_shortened(section, entry.structured)

    def add_row(self, section: EvidenceSection, row: list[str]) -> None:
        if len(section.rows) >= MAX_ROWS:
            return
        fingerprint = tuple(row)
        seen = self._seen.setdefault(section.key, set())
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        section.rows.append(row)

    def merge_row(
        self,
        section: EvidenceSection,
        fingerprint: tuple[str, str],
        row: list[str],
        *,
        sets: tuple[int, ...] = (),
        counted: Callable[[], None],
    ) -> None:
        """Append ``row``, or fold it into the row that says the same thing.

        ``sets`` names the columns that are a set written down — ledger ids,
        agent names — and those are the only cells a merge touches. Every
        other cell is the first occurrence's, untouched: the text belongs to
        whoever wrote it, and a confidence or a severity is never merged,
        averaged or raised.
        """
        index = self._merged.setdefault(section.key, {})
        at = index.get(fingerprint)
        if at is None:
            if len(section.rows) >= MAX_ROWS:
                return
            index[fingerprint] = len(section.rows)
            section.rows.append(row)
            return
        kept = section.rows[at]
        for column in sets:
            if column < len(kept) and column < len(row):
                kept[column] = merge_cell(kept[column], row[column])
        counted()

    def add_item(self, section: EvidenceSection, item: str) -> None:
        if item and item not in section.items and len(section.items) < MAX_ROWS:
            section.items.append(item)

    def result(self) -> list[EvidenceSection]:
        return [
            self._by_key[key]
            for key in self._order
            if self._by_key[key].rows
            or self._by_key[key].items
            or self._by_key[key].text
            or self._by_key[key].kind == "kv"
        ]


# What a section's ``source`` may say and still count as grounded on its own.
# A tool section is grounded by the entry ids it cites, never by naming a tool:
# a builder that produced rows without recording which call they came from is
# the defect ``sections_without_evidence`` exists to surface.
_GROUNDED_SOURCES = frozenset({"routing", "finding"})


def section_is_grounded(section: EvidenceSection) -> bool:
    """Whether a section can name what it was built from.

    Either it cites ledger entries, or it came from something that is itself an
    answer rather than a derivation: the routing minimum, an agent's finding,
    or an artifact an agent established.
    """
    if section.evidence_ids:
        return True
    source = section.source or ""
    return source in _GROUNDED_SOURCES or source.startswith("artifact:")


def _text(value: Any) -> str:
    """One cell, as a string a table can hold."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | tuple):
        return ", ".join(_text(v) for v in value)[:400]
    if isinstance(value, dict):
        return ", ".join(f"{k}={_text(v)}" for k, v in value.items())[:400]
    return str(value)[:400]


# ---------------------------------------------------------------------------
# Per-tool builders
# ---------------------------------------------------------------------------


def our_own_words(data: Any) -> frozenset[str]:
    """The keys of ``data`` that are this system talking, not the tool.

    A key-value table is a table of facts about the sample, and a row reading
    "shortened | {\'/strings\': …}" is neither a fact about the sample nor
    something a reader of this report can act on; the sentence below the table
    says it in words instead. The bookkeeping key is whichever one it ended up
    under, so a tool that owns the ordinary name does not leave the fallback
    printed as a field.
    """
    ours = our_key_in(data)
    return frozenset({BOOKKEEPING_KEY, "truncated"} | ({ours} if ours else set()))


def shortened_sentence(data: dict[str, Any]) -> str:
    """One sentence for an answer this system had to shorten, or ``""``.

    The tool answered in full and the guardrail kept what fits, so the table
    below is a page of the answer rather than all of it. Said once, in words,
    because the reader of a report needs to know a list is partial far more
    than they need the arithmetic.
    """
    book = data.get(our_key_in(data))
    if not isinstance(book, dict) or not book:
        return ""
    named = []
    for path, row in list(book.items())[:3]:
        if not isinstance(row, dict):
            continue
        left = int(row.get("omitted") or row.get("omitted_chars") or 0)
        what = "rows" if "omitted" in row else "characters"
        named.append(f"{path} ({left} {what} not shown)")
    if not named:
        return ""
    return "This answer was shortened to fit the analyst's budget: " + ", ".join(named) + "."


def note_if_shortened(section: Any, data: Any) -> None:
    """Put the sentence under the section, once.

    Called from ``credit``, so it reaches the section a dedicated builder
    filled as well as the generic key-value one: ``strings`` and ``pe_info``
    are exactly the tools whose answers are large enough to be shortened, and
    they are the ones with builders of their own.
    """
    if not isinstance(data, dict):
        return
    said = shortened_sentence(data)
    if said and said not in (section.text or ""):
        section.text = f"{section.text}\n\n{said}".strip() if section.text else said


def _identity(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    section = acc.get("identity", "Sample identity", "kv", columns=["Field", "Value"])
    ours = our_own_words(data)
    for key, value in data.items():
        if key in {"error", "tool"} or key in ours or value in (None, "", [], {}):
            continue
        acc.add_row(section, [key.replace("_", " "), _text(value)])
    acc.credit(section, entry)


# The three schemes ``signing_info`` can answer under. Read in this order so
# an older entry — one recorded when the tool answered about all three at once
# — still puts Authenticode first, which is the order that report was written
# in.
_SIGNING_SCHEMES = ("authenticode", "apk", "macho")


def _signing(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """The signature row, for the format the sample was routed as.

    One row, and only when there is a scheme to report one under. The payload
    also carries the routed ``format`` and, for a format with no code-signing
    scheme at all, ``applicable: False`` — neither is a fact about the sample:
    the first repeats what ``identify_file`` already says two rows above, and
    the second is a statement about what this tool looks for, printed under the
    heading that exists for what was found. A sample whose format has no
    signing scheme therefore gets no signing row, which is what the table said
    before the tool reported all three schemes at once.

    A row per scheme rather than a sentence, because the sentence is the
    console's to build (``identitySection.signingSentence``) and the export
    keeps the tool's own words.
    """
    rows = [
        [scheme, _text(data[scheme])]
        for scheme in _SIGNING_SCHEMES
        if data.get(scheme) not in (None, "", [], {})
    ]
    if not rows:
        return
    section = acc.get("identity", "Sample identity", "kv", columns=["Field", "Value"])
    for row in rows:
        acc.add_row(section, row)
    acc.credit(section, entry)


def _binary_info(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """The structural facts of a PE, ELF, Mach-O or APK, one table per shape."""
    prefix = entry.tool.split("_")[0]

    header = acc.get(f"{prefix}_header", f"{prefix.upper()} header", "kv")
    for key in (
        "machine",
        "timestamp",
        "subsystem",
        "entry_point",
        "is_dll",
        "size",
        "bitness",
        "endianness",
        "interpreter",
        "package",
        "version_name",
        "min_sdk",
        "target_sdk",
        "pdb_path",
        "filetype",
        "flags",
    ):
        if key in data and data[key] not in (None, "", [], {}):
            acc.add_row(header, [key.replace("_", " "), _text(data[key])])
    acc.credit(header, entry)

    sections = data.get("sections")
    if isinstance(sections, list) and sections:
        table = acc.get(
            f"{prefix}_sections",
            f"{prefix.upper()} sections",
            "table",
            columns=["Name", "Virtual address", "Virtual size", "Raw size", "Entropy"],
        )
        for row in sections[:MAX_ROWS]:
            if not isinstance(row, dict):
                continue
            acc.add_row(
                table,
                [
                    _text(row.get("name")),
                    _text(row.get("virtual_address")),
                    _text(row.get("virtual_size")),
                    _text(row.get("raw_size")),
                    _text(row.get("entropy")),
                ],
            )
        acc.credit(table, entry)

    imports = data.get("imports")
    if isinstance(imports, list) and imports:
        table = acc.get(
            f"{prefix}_imports",
            f"{prefix.upper()} imports",
            "table",
            columns=["Library", "Function"],
        )
        for row in imports[:MAX_ROWS]:
            if not isinstance(row, dict):
                continue
            acc.add_row(table, [_text(row.get("dll")), _text(row.get("function"))])
        acc.credit(table, entry)

    exports = data.get("exports")
    if isinstance(exports, list) and exports:
        listing = acc.get(f"{prefix}_exports", f"{prefix.upper()} exports", "list")
        for name in exports[:MAX_ROWS]:
            acc.add_item(listing, _text(name))
        acc.credit(listing, entry)

    permissions = data.get("permissions")
    if isinstance(permissions, list) and permissions:
        listing = acc.get("apk_permissions", "Declared permissions", "list")
        for name in permissions[:MAX_ROWS]:
            acc.add_item(listing, _text(name))
        acc.credit(listing, entry)

    component_keys = ("activities", "services", "receivers", "providers")
    if any(isinstance(data.get(k), list) and data.get(k) for k in component_keys):
        table = acc.get("apk_components", "Declared components", "table", columns=["Kind", "Name"])
        for kind in component_keys:
            for name in (data.get(kind) or [])[:MAX_ROWS]:
                acc.add_row(table, [kind[:-1], _text(name)])
        acc.credit(table, entry)

    packers = data.get("packer_signatures")
    if isinstance(packers, list) and packers:
        table = acc.get(
            "packer_signatures", "Packer section matches", "table", columns=["Packer", "Sections"]
        )
        for row in packers[:MAX_ROWS]:
            if isinstance(row, dict):
                acc.add_row(table, [_text(row.get("name")), _text(row.get("sections"))])
            else:
                acc.add_row(table, [_text(row), ""])
        acc.credit(table, entry)


def _iocs(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("iocs")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "iocs",
        "Indicators recovered from the sample",
        "table",
        columns=["Kind", "Value", "Notes", "Evidence"],
    )
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        # Fingerprinted rather than compared whole: the same endpoint read by
        # two tools arrives with two sets of notes and, defanged by one of
        # them, two spellings. The first occurrence's notes are what the row
        # keeps; what the second brings is the id of the call it came from.
        acc.merge_row(
            table,
            indicator_fingerprint(row.get("kind"), row.get("value")),
            [_text(row.get("kind")), _text(row.get("value")), _text(row.get("notes")), entry.id],
            sets=(3,),
            counted=acc.merges.indicator,
        )
    acc.credit(table, entry)


def _strings(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("strings")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get("strings", "Printable strings", "table", columns=["Offset", "Encoding", "Text"])
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table, [_text(row.get("offset")), _text(row.get("enc")), _text(row.get("text"))]
        )
    acc.credit(table, entry)


def _yara(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    matches = data.get("matches")
    if not isinstance(matches, list) or not matches:
        return
    table = acc.get("yara_matches", "YARA rule matches", "table", columns=["Rule", "Tags", "Where"])
    for row in matches[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(row.get("rule") or row.get("name")),
                _text(row.get("tags")),
                _text(row.get("strings") or row.get("offsets") or row.get("meta")),
            ],
        )
    acc.credit(table, entry)


def _sigma(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    matches = data.get("matches")
    if not isinstance(matches, list) or not matches:
        return
    table = acc.get(
        "sigma_matches",
        "Sigma rule matches",
        "table",
        columns=["Rule", "Level", "Technique", "Matched fields"],
    )
    for row in matches[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        raw_meta = row.get("meta")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        acc.add_row(
            table,
            [
                _text(row.get("title") or row.get("rule") or row.get("id")),
                _text(row.get("level") or meta.get("level")),
                _text(sigma_technique_ids(row)),
                _text(row.get("matched_fields")),
            ],
        )
    acc.credit(table, entry)


def _capa(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("capabilities")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "capa_capabilities",
        "capa capabilities",
        "table",
        columns=["Namespace", "Rule", "ATT&CK", "MBC"],
    )
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(row.get("namespace")),
                _text(row.get("rule")),
                _text(row.get("attck")),
                _text(row.get("mbc")),
            ],
        )
    acc.credit(table, entry)


def _sandbox_processes(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("processes")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "sandbox_processes",
        "Processes observed",
        "table",
        columns=["PID", "Parent", "Name", "Command line"],
    )
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(row.get("pid")),
                _text(row.get("ppid")),
                _text(row.get("name")),
                _text(row.get("command_line")),
            ],
        )
    acc.credit(table, entry)


def _sandbox_network(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    table = acc.get(
        "sandbox_network",
        "Network activity observed",
        "table",
        columns=["Kind", "Endpoint", "Detail"],
    )
    added = False
    for kind in ("dns", "domains", "hosts", "http", "tcp", "udp", "icmp", "tls"):
        rows = data.get(kind)
        if not isinstance(rows, list):
            continue
        for row in rows[:MAX_ROWS]:
            endpoint, detail = _endpoint_of(kind, row)
            if not endpoint:
                continue
            acc.add_row(table, [kind, endpoint, detail])
            added = True
    if added:
        acc.credit(table, entry)


def _endpoint_of(kind: str, row: Any) -> tuple[str, str]:
    """The address a network row is about, and whatever else it carries."""
    if isinstance(row, str):
        return row, ""
    if not isinstance(row, dict):
        return "", ""
    for key in ("request", "hostname", "domain", "host", "uri", "ip", "dst", "name", "ja3", "sni"):
        value = row.get(key)
        if isinstance(value, str) and value:
            detail = {k: v for k, v in row.items() if k != key and v not in (None, "", [], {})}
            return value, _text(detail)
    return "", ""


def _sandbox_signatures(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("signatures")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "sandbox_signatures",
        "Sandbox signature hits",
        "table",
        columns=["Name", "Severity", "Description"],
    )
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [_text(row.get("name")), _text(row.get("severity")), _text(row.get("description"))],
        )
    acc.credit(table, entry)


def _sandbox_dropped(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("dropped")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "sandbox_dropped_files",
        "Files written",
        "table",
        columns=["Name", "Path", "Size", "SHA-256"],
    )
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(row.get("name")),
                _text(row.get("path")),
                _text(row.get("size")),
                _text(row.get("sha256")),
            ],
        )
    acc.credit(table, entry)


def _sandbox_registry(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("registry")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "sandbox_registry",
        "Registry activity",
        "table",
        columns=["Key", "Operation", "Value"],
    )
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [_text(row.get("key")), _text(row.get("operation")), _text(row.get("value"))],
        )
    acc.credit(table, entry)


def _sandbox_apis(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("apis")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "sandbox_api_calls",
        "API calls observed",
        "table",
        columns=["API", "Calls", "Processes", "First arguments"],
    )
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(row.get("api")),
                _text(row.get("count")),
                _text(row.get("processes")),
                _text(row.get("first_args")),
            ],
        )
    acc.credit(table, entry)


def _sandbox_mutexes(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    names = data.get("mutexes")
    if not isinstance(names, list) or not names:
        return
    listing = acc.get("sandbox_mutexes", "Mutexes", "list")
    for name in names[:MAX_ROWS]:
        acc.add_item(listing, _text(name))
    acc.credit(listing, entry)


def _sandbox_services(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    table = acc.get(
        "sandbox_services_and_tasks",
        "Services, tasks and commands",
        "table",
        columns=["Kind", "Value"],
    )
    added = False
    for kind in ("services", "tasks", "commands"):
        for value in data.get(kind) or []:
            acc.add_row(table, [kind[:-1] if kind != "commands" else "command", _text(value)])
            added = True
    if added:
        acc.credit(table, entry)


def _sandbox_section(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """One named section of the sandbox report, whatever shape it turned out to be."""
    name = _text(data.get("section")) or "sandbox"
    rows = data.get("rows")
    if isinstance(rows, list) and rows and all(isinstance(r, dict) for r in rows):
        _generic_table(acc, entry, rows, key=f"sandbox_{name}", title=f"Sandbox: {name}")
        return
    value = data.get("value")
    if isinstance(value, dict):
        _generic_kv(acc, entry, value, key=f"sandbox_{name}", title=f"Sandbox: {name}")
        return
    if rows or value:
        section = acc.get(f"sandbox_{name}", f"Sandbox: {name}", "text")
        section.text = _text(rows or value)[:MAX_TEXT_CHARS]
        acc.credit(section, entry)


def _pcap(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    summary = data.get("summary")
    if not summary:
        return
    section = acc.get("pcap_summary", "Capture summary", "text")
    section.text = str(summary)[:MAX_TEXT_CHARS]
    acc.credit(section, entry)


# Reverse-engineering tools name a function and answer about it. The report
# does not paste decompilation, but which functions an analyst actually looked
# at is the one durable fact of a Ghidra or radare2 loop.
_FUNCTION_TOOLS = frozenset(
    {
        "decompile_function",
        "decompile",
        "disassemble_function",
        "get_function",
        "analyze_function",
        "pdf",
        "pdc",
    }
)
_FUNCTION_LIST_TOOLS = frozenset({"list_functions", "get_functions", "afl", "list_methods"})


def _functions_examined(acc: _Sections, entry: LedgerEntry, _data: Any) -> None:
    section = acc.get("functions_examined", "Functions examined", "list")
    label = entry.symbol or entry.tool
    acc.add_item(section, f"{label} ({entry.tool})")
    acc.credit(section, entry)


_BUILDERS: dict[str, Any] = {
    "identify_file": _identity,
    "hashes": _identity,
    "signing_info": _signing,
    "pe_info": _binary_info,
    "elf_info": _binary_info,
    "macho_info": _binary_info,
    "apk_info": _binary_info,
    "strings": _strings,
    "iocs_from_text": _iocs,
    "iocs_from_file": _iocs,
    "yara_scan": _yara,
    "sigma_match": _sigma,
    "sigma_match_sandbox": _sigma,
    "capa": _capa,
    "sandbox_processes": _sandbox_processes,
    "sandbox_network": _sandbox_network,
    "sandbox_signatures": _sandbox_signatures,
    "sandbox_dropped_files": _sandbox_dropped,
    "sandbox_registry_ops": _sandbox_registry,
    "sandbox_api_calls": _sandbox_apis,
    "sandbox_mutexes": _sandbox_mutexes,
    "sandbox_services_and_tasks": _sandbox_services,
    "sandbox_report_section": _sandbox_section,
    "pcap_summary": _pcap,
}


# ---------------------------------------------------------------------------
# Generic fallbacks
# ---------------------------------------------------------------------------


def _generic_table(
    acc: _Sections,
    entry: LedgerEntry,
    rows: list[Any],
    *,
    key: str = "",
    title: str = "",
) -> None:
    """A JSON array of objects, as a table over the union of their keys."""
    dicts = [row for row in rows if isinstance(row, dict)]
    if not dicts:
        return
    columns: list[str] = []
    for row in dicts:
        for column in row:
            if column not in columns:
                columns.append(str(column))
    section = acc.get(
        key or f"tool_{entry.tool}",
        title or entry.tool.replace("_", " ").capitalize(),
        "table",
        columns=columns,
    )
    for column in columns:
        if column not in section.columns:
            section.columns.append(column)
    for row in dicts[:MAX_ROWS]:
        acc.add_row(section, [_text(row.get(column)) for column in section.columns])
    acc.credit(section, entry)


def _generic_kv(
    acc: _Sections,
    entry: LedgerEntry,
    data: dict[str, Any],
    *,
    key: str = "",
    title: str = "",
) -> None:
    section = acc.get(
        key or f"tool_{entry.tool}",
        title or entry.tool.replace("_", " ").capitalize(),
        "kv",
        columns=["Field", "Value"],
    )
    ours = our_own_words(data)
    for name, value in data.items():
        if name in {"tool"} or name in ours or value in (None, "", [], {}):
            continue
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            _generic_table(
                acc,
                entry,
                value,
                key=f"{section.key}_{name}",
                title=f"{section.title}: {name.replace('_', ' ')}",
            )
            continue
        acc.add_row(section, [str(name).replace("_", " "), _text(value)])
    acc.credit(section, entry)


def _generic_text(acc: _Sections, entry: LedgerEntry) -> None:
    if not entry.output.strip():
        return
    section = acc.get(f"tool_{entry.tool}", entry.tool.replace("_", " ").capitalize(), "text")
    if not section.text:
        section.text = entry.output[:MAX_TEXT_CHARS]
    acc.credit(section, entry)


def _fallback(acc: _Sections, entry: LedgerEntry) -> None:
    data = entry.structured
    if isinstance(data, dict):
        _generic_kv(acc, entry, data)
        return
    if isinstance(data, list):
        if any(isinstance(row, dict) for row in data):
            _generic_table(acc, entry, data)
        else:
            section = acc.get(
                f"tool_{entry.tool}", entry.tool.replace("_", " ").capitalize(), "list"
            )
            for item in data[:MAX_ROWS]:
                acc.add_item(section, _text(item))
            acc.credit(section, entry)
        return
    _generic_text(acc, entry)


# ---------------------------------------------------------------------------
# Agent-contributed sections
# ---------------------------------------------------------------------------


def _artifact_sections(acc: _Sections, isrs: dict[str, Any]) -> None:
    """The tables the analysts established, grouped by the kind they named."""
    for agent, isr in (isrs or {}).items():
        for artifact in list(getattr(isr, "artifacts", None) or []):
            kind = (getattr(artifact, "kind", "") or "artifact").strip() or "artifact"
            columns = list(getattr(artifact, "columns", None) or [])
            rows = list(getattr(artifact, "rows", None) or [])
            label = getattr(artifact, "label", "") or kind
            source = getattr(artifact, "source", "") or agent
            if rows:
                section = acc.get(
                    f"artifact_{kind}",
                    kind.replace("_", " ").capitalize(),
                    "table",
                    columns=columns or ["Value"],
                )
                section.source = f"artifact:{source}"
                for row in rows[:MAX_ROWS]:
                    acc.add_row(section, [_text(cell) for cell in row])
            else:
                section = acc.get(
                    f"artifact_{kind}",
                    kind.replace("_", " ").capitalize(),
                    "table",
                    columns=["Label", "Value"],
                )
                section.source = f"artifact:{source}"
                acc.add_row(section, [_text(label), _text(getattr(artifact, "value", ""))])
            for entry_id in getattr(artifact, "evidence_ids", None) or []:
                acc.cite(section, str(entry_id))


# What the Techniques column writes beside an id this run did not publish. The
# reason itself is under the ATT&CK matrix, where every unpublished id is named
# with the check's own sentence; here there is room for the fact only, and
# printing the fact in words is the point — a run that published none of the
# three enterprise-only ids it printed said nothing at all.
NOT_PUBLISHED_MARKER = "claimed, not published"


def _technique_cell(technique_ids: Any, published: frozenset[str] | None) -> str:
    """The Techniques cell for one finding, marking what is not published.

    ``None`` is a caller with no published list to compare against, which is
    not a claim either way and marks nothing. An empty set is a run that
    published no technique at all, and every id it printed is marked — which is
    the run this exists for.
    """
    written: list[str] = []
    for raw in technique_ids or []:
        tid = str(raw or "").strip()
        if not tid:
            continue
        if published is None or tid.upper() in published:
            written.append(tid)
        else:
            written.append(f"{tid} ({NOT_PUBLISHED_MARKER})")
    return ", ".join(written)


def _findings_section(
    acc: _Sections, isrs: dict[str, Any], published: frozenset[str] | None = None
) -> None:
    """Every analyst finding in one table, with what each was drawn from."""
    section: EvidenceSection | None = None
    for agent, isr in (isrs or {}).items():
        for finding in list(getattr(isr, "findings", None) or []):
            if section is None:
                section = acc.get(
                    "findings",
                    "Findings",
                    "table",
                    columns=["Agent", "Finding", "Techniques", "Confidence", "Evidence"],
                    source="finding",
                )
            # Two analysts reaching the same conclusion about the same
            # technique is one finding with two names against it, not two
            # findings. The confidence stays the first one's: agreement is
            # something a reader draws from the agent list, never something
            # this arithmetic asserts by raising a number nobody wrote.
            acc.merge_row(
                section,
                finding_fingerprint(
                    getattr(finding, "technique_ids", []) or [],
                    getattr(finding, "title", ""),
                ),
                [
                    str(agent),
                    _text(getattr(finding, "title", "")),
                    _technique_cell(getattr(finding, "technique_ids", []) or [], published),
                    f"{float(getattr(finding, 'confidence', 0.0) or 0.0):.2f}",
                    _text(getattr(finding, "evidence_ids", []) or []),
                ],
                sets=(0, 4),
                counted=acc.merges.finding,
            )
            for entry_id in getattr(finding, "evidence_ids", None) or []:
                acc.cite(section, str(entry_id))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_sections(
    ledger: list[LedgerEntry],
    isrs: dict[str, AgentISR] | None = None,
    file_type: str = "unknown",
    platform: str = "unknown",
    merges: MergeTally | None = None,
    published_techniques: frozenset[str] | None = None,
) -> list[EvidenceSection]:
    """Every section this run's evidence supports, in the order it was gathered.

    ``file_type`` and ``platform`` are the routing minimum, carried so a run
    that identified nothing still says what it was working on rather than
    opening with an empty identity block. ``merges`` is filled in with what
    the indicator and finding tables folded, for the run summary to state.

    ``published_techniques`` is the validated ``ttp_mappings``, so the Findings
    table can say which of the ids it prints this run did not publish. ``None``
    is a caller with no such list to compare against, which is not a claim
    either way and marks nothing; an empty set is a run that published no
    technique at all, and every id it prints is marked.
    """
    acc = _Sections(merges)

    identity = acc.get("identity", "Sample identity", "kv", columns=["Field", "Value"])
    identity.source = "routing"
    if file_type and file_type != "unknown":
        acc.add_row(identity, ["file type", file_type])
    if platform and platform != "unknown":
        acc.add_row(identity, ["platform", platform])

    for entry in ledger or []:
        if not entry.ok:
            # A failed call is on the record in the ledger and in the run
            # summary; it has no content to build a section out of.
            continue
        if entry.tool in _FUNCTION_LIST_TOOLS or entry.tool in _FUNCTION_TOOLS:
            _functions_examined(acc, entry, entry.structured)
            continue
        builder = _BUILDERS.get(entry.tool)
        data = entry.structured
        if builder is not None and isinstance(data, dict):
            if data.get("error"):
                continue
            builder(acc, entry, data)
            continue
        _fallback(acc, entry)

    _artifact_sections(acc, isrs or {})
    _findings_section(acc, isrs or {}, published_techniques)
    return acc.result()
