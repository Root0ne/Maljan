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
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

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

    def __init__(self) -> None:
        self._by_key: dict[str, EvidenceSection] = {}
        self._order: list[str] = []
        self._seen: dict[str, set[tuple[str, ...]]] = {}

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

    def add_row(self, section: EvidenceSection, row: list[str]) -> None:
        if len(section.rows) >= MAX_ROWS:
            return
        fingerprint = tuple(row)
        seen = self._seen.setdefault(section.key, set())
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        section.rows.append(row)

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


def _identity(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    section = acc.get("identity", "Sample identity", "kv", columns=["Field", "Value"])
    section.source = "tool"
    for key, value in data.items():
        if key in {"error", "tool"} or value in (None, "", [], {}):
            continue
        acc.add_row(section, [key.replace("_", " "), _text(value)])
    acc.cite(section, entry.id)


def _binary_info(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """The structural facts of a PE, ELF, Mach-O or APK, one table per shape."""
    prefix = entry.tool.split("_")[0]

    header = acc.get(f"{prefix}_header", f"{prefix.upper()} header", "kv")
    header.source = "tool"
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
    acc.cite(header, entry.id)

    sections = data.get("sections")
    if isinstance(sections, list) and sections:
        table = acc.get(
            f"{prefix}_sections",
            f"{prefix.upper()} sections",
            "table",
            columns=["Name", "Virtual address", "Virtual size", "Raw size", "Entropy"],
        )
        table.source = "tool"
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
        acc.cite(table, entry.id)

    imports = data.get("imports")
    if isinstance(imports, list) and imports:
        table = acc.get(
            f"{prefix}_imports",
            f"{prefix.upper()} imports",
            "table",
            columns=["Library", "Function", "Category"],
        )
        table.source = "tool"
        for row in imports[:MAX_ROWS]:
            if not isinstance(row, dict):
                continue
            acc.add_row(
                table,
                [_text(row.get("dll")), _text(row.get("function")), _text(row.get("category"))],
            )
        acc.cite(table, entry.id)

    exports = data.get("exports")
    if isinstance(exports, list) and exports:
        listing = acc.get(f"{prefix}_exports", f"{prefix.upper()} exports", "list")
        listing.source = "tool"
        for name in exports[:MAX_ROWS]:
            acc.add_item(listing, _text(name))
        acc.cite(listing, entry.id)

    permissions = data.get("permissions")
    if isinstance(permissions, list) and permissions:
        listing = acc.get("apk_permissions", "Declared permissions", "list")
        listing.source = "tool"
        for name in permissions[:MAX_ROWS]:
            acc.add_item(listing, _text(name))
        acc.cite(listing, entry.id)

    component_keys = ("activities", "services", "receivers", "providers")
    if any(isinstance(data.get(k), list) and data.get(k) for k in component_keys):
        table = acc.get("apk_components", "Declared components", "table", columns=["Kind", "Name"])
        table.source = "tool"
        for kind in component_keys:
            for name in (data.get(kind) or [])[:MAX_ROWS]:
                acc.add_row(table, [kind[:-1], _text(name)])
        acc.cite(table, entry.id)

    packers = data.get("packer_signatures")
    if isinstance(packers, list) and packers:
        table = acc.get(
            "packer_signatures", "Packer section matches", "table", columns=["Packer", "Sections"]
        )
        table.source = "tool"
        for row in packers[:MAX_ROWS]:
            if isinstance(row, dict):
                acc.add_row(table, [_text(row.get("name")), _text(row.get("sections"))])
            else:
                acc.add_row(table, [_text(row), ""])
        acc.cite(table, entry.id)


def _iocs(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("iocs")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "iocs", "Indicators recovered from the sample", "table", columns=["Kind", "Value", "Notes"]
    )
    table.source = "tool"
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [_text(row.get("kind")), _text(row.get("value")), _text(row.get("notes"))],
        )
    acc.cite(table, entry.id)


def _strings(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = data.get("strings")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get("strings", "Printable strings", "table", columns=["Offset", "Encoding", "Text"])
    table.source = "tool"
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table, [_text(row.get("offset")), _text(row.get("enc")), _text(row.get("text"))]
        )
    acc.cite(table, entry.id)


def _yara(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    matches = data.get("matches")
    if not isinstance(matches, list) or not matches:
        return
    table = acc.get("yara_matches", "YARA rule matches", "table", columns=["Rule", "Tags", "Where"])
    table.source = "tool"
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
    acc.cite(table, entry.id)


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
    table.source = "tool"
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
                _text(row.get("technique_ids") or meta.get("technique_ids")),
                _text(row.get("matched_fields")),
            ],
        )
    acc.cite(table, entry.id)


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
    table.source = "tool"
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
    acc.cite(table, entry.id)


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
    table.source = "tool"
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
    acc.cite(table, entry.id)


def _sandbox_network(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    table = acc.get(
        "sandbox_network",
        "Network activity observed",
        "table",
        columns=["Kind", "Endpoint", "Detail"],
    )
    table.source = "tool"
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
        acc.cite(table, entry.id)


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
    table.source = "tool"
    for row in rows[:MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [_text(row.get("name")), _text(row.get("severity")), _text(row.get("description"))],
        )
    acc.cite(table, entry.id)


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
    table.source = "tool"
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
    acc.cite(table, entry.id)


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
        section.source = "tool"
        section.text = _text(rows or value)[:MAX_TEXT_CHARS]
        acc.cite(section, entry.id)


def _pcap(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    summary = data.get("summary")
    if not summary:
        return
    section = acc.get("pcap_summary", "Capture summary", "text")
    section.source = "tool"
    section.text = str(summary)[:MAX_TEXT_CHARS]
    acc.cite(section, entry.id)


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
    section.source = "tool"
    label = entry.symbol or entry.tool
    acc.add_item(section, f"{label} ({entry.tool})")
    acc.cite(section, entry.id)


_BUILDERS: dict[str, Any] = {
    "identify_file": _identity,
    "hashes": _identity,
    "signing_info": _identity,
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
    section.source = "tool"
    for column in columns:
        if column not in section.columns:
            section.columns.append(column)
    for row in dicts[:MAX_ROWS]:
        acc.add_row(section, [_text(row.get(column)) for column in section.columns])
    acc.cite(section, entry.id)


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
    section.source = "tool"
    for name, value in data.items():
        if name in {"tool"} or value in (None, "", [], {}):
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
    acc.cite(section, entry.id)


def _generic_text(acc: _Sections, entry: LedgerEntry) -> None:
    if not entry.output.strip():
        return
    section = acc.get(f"tool_{entry.tool}", entry.tool.replace("_", " ").capitalize(), "text")
    section.source = "tool"
    if not section.text:
        section.text = entry.output[:MAX_TEXT_CHARS]
    acc.cite(section, entry.id)


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
            section.source = "tool"
            for item in data[:MAX_ROWS]:
                acc.add_item(section, _text(item))
            acc.cite(section, entry.id)
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
                section.source = f"agent:{source}"
                for row in rows[:MAX_ROWS]:
                    acc.add_row(section, [_text(cell) for cell in row])
            else:
                section = acc.get(
                    f"artifact_{kind}",
                    kind.replace("_", " ").capitalize(),
                    "table",
                    columns=["Label", "Value"],
                )
                section.source = f"agent:{source}"
                acc.add_row(section, [_text(label), _text(getattr(artifact, "value", ""))])
            for entry_id in getattr(artifact, "evidence_ids", None) or []:
                acc.cite(section, str(entry_id))


def _findings_section(acc: _Sections, isrs: dict[str, Any]) -> None:
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
                    source="agent",
                )
            acc.add_row(
                section,
                [
                    str(agent),
                    _text(getattr(finding, "title", "")),
                    _text(getattr(finding, "technique_ids", []) or []),
                    f"{float(getattr(finding, 'confidence', 0.0) or 0.0):.2f}",
                    _text(getattr(finding, "evidence_ids", []) or []),
                ],
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
) -> list[EvidenceSection]:
    """Every section this run's evidence supports, in the order it was gathered.

    ``file_type`` and ``platform`` are the routing minimum, carried so a run
    that identified nothing still says what it was working on rather than
    opening with an empty identity block.
    """
    acc = _Sections()

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
    _findings_section(acc, isrs or {})
    return acc.result()
