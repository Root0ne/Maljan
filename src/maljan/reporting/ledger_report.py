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

from collections import Counter
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from maljan.agents.output_shortening import BOOKKEEPING_KEY, our_key_in
from maljan.analysis import behaviour_code
from maljan.analysis.technique_ids import (
    says_no_technique,
    sigma_technique_ids,
    technique_ids_in,
)
from maljan.core.reputation import reputation_of
from maljan.core.tool_declarations import first, select
from maljan.core.undeclared_tools import (
    CODE_LISTING_KINDS,
    DECOMPILE_KINDS,
    CodePart,
    address_arguments,
    names_itself,
)
from maljan.reporting import tool_kinds
from maljan.reporting.dedupe import (
    MergeTally,
    finding_fingerprint,
    indicator_fingerprint,
    merge_cell,
)
from maljan.reporting.models import OPEN_QUESTION_SOURCE, EvidenceSection
from maljan.schemas.evidence import answer_not_shown
from maljan.schemas.isr_models import would_answer_text
from maljan.schemas.sandbox_document import DNS_NAME_KEYS, dns_name_key
from maljan.utils.marked_cut import marked_cut

if TYPE_CHECKING:
    from maljan.schemas.evidence import LedgerEntry
    from maljan.schemas.isr_models import AgentISR

# A text section never becomes the report. Anything longer than this is a tool
# output that wants reading in the evidence endpoint, not pasting into a
# document; a text cut here ends in the cut mark and says where it is whole.
MAX_TEXT_CHARS = 4000

# How many rows one generated table may carry. A strings dump or a busy process
# list would otherwise turn a report into a log file. A table that reaches it
# says how many rows it left out and where they are (``ROWS_LEFT_OUT``).
MAX_ROWS = 200

# How much of one cell a table prints; a longer cell ends in the cut mark.
# A function's code a table holds is never cut to it (``_code_or_text``):
# only a one-line fact is, in a section citing the entry that holds it whole.
CELL_CHARS = 400

ROWS_LEFT_OUT = (
    "{rest:,} more rows not shown here; the evidence endpoint carries every one under {ids}."
)
TEXT_CUT = (
    "Cut here at {shown:,} of {total:,} characters; the evidence endpoint carries it "
    "whole under {ids}."
)


def _cut_text(text: str, ids: str) -> str:
    """``text`` whole, or cut to ``MAX_TEXT_CHARS`` with the sentence saying where it is whole."""
    if len(text) <= MAX_TEXT_CHARS:
        return text
    shown = marked_cut(text, MAX_TEXT_CHARS)
    return f"{shown}\n\n{TEXT_CUT.format(shown=len(shown), total=len(text), ids=ids)}"


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
        # Rows a table could not carry past ``MAX_ROWS``, per section, said
        # under it when the sections are handed over.
        self._left_out: dict[str, int] = {}
        # The ids each section cites, and every id any section cites, so a
        # citation and the question "was this entry drawn" are one lookup.
        self._cited: dict[str, set[str]] = {}
        self._credited: set[str] = set()

    def _full(self, section: EvidenceSection, size: int) -> bool:
        if size < MAX_ROWS:
            return False
        self._left_out[section.key] = self._left_out.get(section.key, 0) + 1
        return True

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

    def credited(self, entry: LedgerEntry) -> bool:
        """Whether any section built so far cites ``entry``."""
        return entry.id in self._credited

    def cite(self, section: EvidenceSection, entry_id: str) -> None:
        if not entry_id:
            return
        held = self._cited.get(section.key)
        if held is None:
            held = self._cited[section.key] = set(section.evidence_ids)
        if entry_id not in held:
            held.add(entry_id)
            section.evidence_ids.append(entry_id)
        self._credited.add(entry_id)

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

    def add_column(self, section: EvidenceSection, name: str, fill: str = "-") -> None:
        """Give a table one more column, each row it holds already ``fill`` under it."""
        if name in section.columns:
            return
        section.columns.append(name)
        for row in section.rows:
            row.append(fill)
        self._seen[section.key] = {tuple(row) for row in section.rows}

    def add_row(self, section: EvidenceSection, row: list[str]) -> None:
        fingerprint = tuple(row)
        seen = self._seen.setdefault(section.key, set())
        if fingerprint in seen:
            return
        if self._full(section, len(section.rows)):
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
            if self._full(section, len(section.rows)):
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
        if item and item not in section.items and not self._full(section, len(section.items)):
            section.items.append(item)

    def result(self) -> list[EvidenceSection]:
        for key, rest in self._left_out.items():
            section = self._by_key[key]
            ids = ", ".join(section.evidence_ids) or "this run's ledger"
            said = ROWS_LEFT_OUT.format(rest=rest, ids=ids)
            if said not in (section.text or ""):
                section.text = f"{section.text}\n\n{said}".strip() if section.text else said
        self._left_out = {}
        # A row wider than its table's columns has every cell headed, by
        # position where nothing names it, so no surface draws a cell headless.
        for section in self._by_key.values():
            if section.columns:
                widest = max((len(row) for row in section.rows), default=0)
                section.columns += [f"Column {i + 1}" for i in range(len(section.columns), widest)]
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
# the defect ``sections_without_evidence`` exists to surface. The "Open
# questions" section is grounded on its own, as an answer the analysts wrote,
# and is no analyst section source (``ANALYST_SECTION_SOURCES``): the ids it
# cites corroborate no value.
_GROUNDED_SOURCES = frozenset({"routing", "finding", OPEN_QUESTION_SOURCE})


def section_is_grounded(section: EvidenceSection) -> bool:
    """Whether a section can name what it was built from.

    Either it cites ledger entries, or it came from something that is itself an
    answer rather than a derivation: the routing minimum, an agent's finding,
    an artifact an agent established, or a question an agent left open.
    """
    if section.evidence_ids:
        return True
    source = section.source or ""
    return source in _GROUNDED_SOURCES or source.startswith("artifact:")


def _whole_text(value: Any) -> str:
    """``value`` as text with no cell's cut, for a text section cut by ``_cut_text``."""
    if isinstance(value, list | tuple):
        return ", ".join(_whole_text(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={_whole_text(v)}" for k, v in value.items())
    return _text(value) if isinstance(value, bool) or value is None else str(value)


def _text(value: Any) -> str:
    """One cell, as a string a table can hold."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | tuple):
        return marked_cut(", ".join(_text(v) for v in value), CELL_CHARS)
    if isinstance(value, dict):
        return marked_cut(", ".join(f"{k}={_text(v)}" for k, v in value.items()), CELL_CHARS)
    return marked_cut(str(value), CELL_CHARS)


def _declares_code(entry: LedgerEntry) -> bool:
    """Whether ``entry`` stored that its answer is code: decompiled, or listed as instructions.

    Read from the kind stored with the entry's facts when it was written,
    never from its tool's name.
    """
    kind = str((entry.facts or {}).get("kind") or "")
    return kind in DECOMPILE_KINDS or kind in CODE_LISTING_KINDS


def _holds_code(value: Any, row: Iterable[Any] = (), declared: bool = False) -> bool:
    """Whether one value of a table is code, kept whole rather than cut to a cell.

    Code spans lines: a one-line value is a table's fact whatever its entry.
    Where the entry declares code (:func:`_declares_code`), every text of more
    than one line is code; anywhere else a text is code when it names the
    function another value of its row names (``FUN_<address>`` under the
    address, or its first instruction at it).
    """
    text = value.strip() if isinstance(value, str) else ""
    if "\n" not in text:
        return False
    if declared:
        return True
    return any(
        names_itself(CodePart(str(other).strip(), text, False))
        for other in row
        if "\n" not in str(other).strip()
    )


def _code_or_text(value: Any, row: Iterable[Any], declared: bool) -> str:
    """One cell: code whole as the entry holds it (:func:`_holds_code`), else as ``_text``."""
    return str(value) if _holds_code(value, row, declared) else _text(value)


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
    # The section is named for the tool that answered, whole: two tools that
    # share a first word ("pe_info", "pe_strip_info") are two sections, not
    # one holding both their rows.
    prefix = entry.tool.removesuffix("_info") or entry.tool

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
        "export_name",
        "version_info",
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
        for row in sections:
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
        for row in imports:
            if not isinstance(row, dict):
                continue
            acc.add_row(table, [_text(row.get("dll")), _text(row.get("function"))])
        acc.credit(table, entry)

    # With the ordinals and addresses when the tool reported them: several
    # exports sharing one address is a fact the names alone hide.
    export_rows = [row for row in data.get("export_rows") or [] if isinstance(row, dict)]
    exports = data.get("exports")
    if export_rows:
        table = acc.get(
            f"{prefix}_exports",
            f"{prefix.upper()} exports",
            "table",
            columns=["Name", "Ordinal", "RVA"],
        )
        for row in export_rows:
            acc.add_row(
                table, [_text(row.get("name")), _text(row.get("ordinal")), _text(row.get("rva"))]
            )
        acc.credit(table, entry)
    elif isinstance(exports, list) and exports:
        listing = acc.get(f"{prefix}_exports", f"{prefix.upper()} exports", "list")
        for name in exports:
            acc.add_item(listing, _text(name))
        acc.credit(listing, entry)

    permissions = data.get("permissions")
    if isinstance(permissions, list) and permissions:
        listing = acc.get("apk_permissions", "Declared permissions", "list")
        for name in permissions:
            acc.add_item(listing, _text(name))
        acc.credit(listing, entry)

    component_keys = ("activities", "services", "receivers", "providers")
    if any(isinstance(data.get(k), list) and data.get(k) for k in component_keys):
        table = acc.get("apk_components", "Declared components", "table", columns=["Kind", "Name"])
        for kind in component_keys:
            # One kind androguard could not read is a ``no: <reason>`` string.
            names = data.get(kind)
            for name in names if isinstance(names, list) else []:
                acc.add_row(table, [kind[:-1], _text(name)])
        acc.credit(table, entry)

    packers = data.get("packer_signatures")
    if isinstance(packers, list) and packers:
        table = acc.get(
            "packer_signatures", "Packer section matches", "table", columns=["Packer", "Sections"]
        )
        for row in packers:
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
    for row in rows:
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
    for row in rows:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table, [_text(row.get("offset")), _text(row.get("enc")), _text(row.get("text"))]
        )
    acc.credit(table, entry)


# The rule tables' titles: ``{tool}`` is the rule tool's declared display name.
RULE_MATCHES_TITLE = "{tool} rule matches"
CAPABILITIES_TITLE = "{tool} capabilities"
# The rule-match tables' section keys, by the declared kind whose rows each
# holds (stored keys, kept for stored-run byte identity).
RULE_TABLE_OF_KIND: dict[str, str] = {
    "event_rules": "sigma_matches",
    "signature_rules": "yara_matches",
}


def titled_tool(title: Any, template: str) -> str:
    """The tool name a rule table's ``title`` gives in ``template``, ``""`` for another title.

    A rule table is titled by the declared display name of the tool whose
    rows it holds, whichever tool of the kind that is; every label printed
    for the table's rows is read back from its title, so a tool swapped in
    for a shipped one is named as itself (a stored report's title is read the
    same way).
    """
    text = str(title or "")
    prefix, _, suffix = template.partition("{tool}")
    if len(text) > len(prefix) + len(suffix) and text.startswith(prefix) and text.endswith(suffix):
        return text[len(prefix) : len(text) - len(suffix)]
    return ""


def _rule_rows(entry: LedgerEntry, data: dict[str, Any], key: str) -> Any:
    """A rule answer's rows: where its declaration says, else under ``key`` as the
    built-in rule tools answer."""
    facts = tool_kinds.declared_facts(entry)
    if facts is not None and facts.rows:
        return select(data, facts.rows)
    return data.get(key)


def _or(declared: Any, own: Any) -> Any:
    """The declared value where the declaration names one, else the row's own field."""
    return own if declared is None else declared


def _declared(entry: LedgerEntry, row: dict[str, Any], name: str) -> Any:
    """The value a rule row holds where its tool's declaration names ``name``, or ``None``."""
    facts = tool_kinds.declared_facts(entry)
    path = facts.values.get(name, "") if facts is not None else ""
    return first(row, path) if path else None


def _declared_techniques(entry: LedgerEntry, row: dict[str, Any]) -> list[str]:
    """The technique ids a rule row names where its tool's declaration says."""
    facts = tool_kinds.declared_facts(entry)
    return tool_kinds.row_technique_ids(row, facts) if facts is not None else []


def _yara(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    matches = _rule_rows(entry, data, "matches")
    if not isinstance(matches, list) or not matches:
        return
    table = acc.get(
        RULE_TABLE_OF_KIND["signature_rules"],
        RULE_MATCHES_TITLE.format(tool=tool_kinds.display_name(entry)),
        "table",
        columns=["Rule", "Tags", "Where"],
    )
    for row in matches:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(_declared(entry, row, "rule") or row.get("rule") or row.get("name")),
                _text(row.get("tags")),
                _text(row.get("strings") or row.get("offsets") or row.get("meta")),
            ],
        )
    acc.credit(table, entry)


def _sigma(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    matches = _rule_rows(entry, data, "matches")
    if not isinstance(matches, list) or not matches:
        return
    table = acc.get(
        RULE_TABLE_OF_KIND["event_rules"],
        RULE_MATCHES_TITLE.format(tool=tool_kinds.display_name(entry)),
        "table",
        columns=["Rule", "Level", "Technique", "Matched fields"],
    )
    for row in matches:
        if not isinstance(row, dict):
            continue
        raw_meta = row.get("meta")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        acc.add_row(
            table,
            [
                _text(
                    _declared(entry, row, "title")
                    or row.get("title")
                    or _declared(entry, row, "rule")
                    or row.get("rule")
                    or row.get("id")
                ),
                _text(row.get("level") or meta.get("level")),
                _text(sigma_technique_ids(row) or _declared_techniques(entry, row)),
                _text(row.get("matched_fields")),
            ],
        )
    acc.credit(table, entry)


def _capa(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    rows = _rule_rows(entry, data, "capabilities")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "capa_capabilities",
        CAPABILITIES_TITLE.format(tool=tool_kinds.display_name(entry)),
        "table",
        columns=["Namespace", "Rule", "ATT&CK", "MBC"],
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(_declared(entry, row, "namespace") or row.get("namespace")),
                _text(_declared(entry, row, "rule") or row.get("rule")),
                _text(row.get("attck") or _declared_techniques(entry, row)),
                _text(row.get("mbc")),
            ],
        )
    acc.credit(table, entry)


def _declared_place(entry: LedgerEntry, row: dict[str, Any], name: str) -> Any:
    """The value a row holds where its tool's declaration places ``name``, or ``None``."""
    facts = tool_kinds.declared_facts(entry)
    path = facts.places.get(name, "") if facts is not None else ""
    return first(row, path) if path else None


def _sandbox_processes(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    # Where the declaration says, so a live sandbox server whose rows are shaped
    # otherwise is drawn as the built-in sandbox's processes are.
    rows = _rule_rows(entry, data, "processes")
    if not isinstance(rows, list) or not rows:
        return
    table = acc.get(
        "sandbox_processes",
        "Processes observed",
        "table",
        columns=["PID", "Parent", "Name", "Command line"],
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        acc.add_row(
            table,
            [
                _text(_or(_declared_place(entry, row, "pid"), row.get("pid"))),
                _text(row.get("ppid")),
                _text(_or(_declared(entry, row, "name"), row.get("name"))),
                _text(_or(_declared(entry, row, "command_line"), row.get("command_line"))),
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
        for row in rows:
            endpoint, detail = _endpoint_of(kind, row)
            if not endpoint:
                continue
            acc.add_row(table, [kind, endpoint, detail])
            added = True
    if added:
        acc.credit(table, entry)


# The keys a network row other than a DNS row names what it is about under,
# in the order read. A DNS row's name is read by the one DNS row reader
# (``schemas.sandbox_document.dns_row_name``), then these past its name keys.
_NON_DNS_ENDPOINT_KEYS = (
    "request",
    "hostname",
    "domain",
    "host",
    "uri",
    "ip",
    "dst",
    "name",
    "ja3",
    "sni",
)


def _endpoint_of(kind: str, row: Any) -> tuple[str, str]:
    """The address a network row is about, and whatever else it carries."""
    if isinstance(row, str):
        return row, ""
    if not isinstance(row, dict):
        return "", ""
    if kind == "dns":
        key = dns_name_key(row)
        keys: tuple[str, ...] = (
            (key,) if key else tuple(k for k in _NON_DNS_ENDPOINT_KEYS if k not in DNS_NAME_KEYS)
        )
    else:
        keys = _NON_DNS_ENDPOINT_KEYS
    for key in keys:
        value = row.get(key)
        if not isinstance(value, str):
            continue
        written = value.strip() if kind == "dns" else value
        if written:
            detail = {k: v for k, v in row.items() if k != key and v not in (None, "", [], {})}
            return written, _text(detail)
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
    tagged = [
        technique_ids_in(row.get("technique_ids")) if isinstance(row, dict) else [] for row in rows
    ]
    if any(tagged):
        # The ids the sandbox tags a signature with, in a column of their own
        # once any signature of the run carries them.
        acc.add_column(table, SIGNATURE_TECHNIQUES_COLUMN)
    with_ids = SIGNATURE_TECHNIQUES_COLUMN in table.columns
    for row, ids in zip(rows, tagged, strict=True):
        if not isinstance(row, dict):
            continue
        cells = [_text(row.get("name")), _text(row.get("severity")), _text(row.get("description"))]
        acc.add_row(table, [*cells, ", ".join(ids) or "-"] if with_ids else cells)
    acc.credit(table, entry)


# The column the sandbox signature table names a signature's techniques under.
SIGNATURE_TECHNIQUES_COLUMN = "Techniques"


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
    for row in rows:
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
    for row in rows:
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
    for row in rows:
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
    for name in names:
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
        section.text = _cut_text(_whole_text(rows or value), entry.id)
        acc.credit(section, entry)


def _sandbox_items(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """A ``sandbox_items`` answer: its items, one row each, under the section they came from."""
    from maljan.analysis.sandbox_sections import SECTION_PREFIXES

    name = _text(data.get("section"))
    if name not in SECTION_PREFIXES:
        return
    rows = [
        {
            "id": item.get("id"),
            "kind": item.get("kind"),
            "source": item.get("source"),
            "fields": item.get("fields"),
        }
        for item in data.get("items") or []
        if isinstance(item, dict)
    ]
    _generic_table(acc, entry, rows, key=f"sandbox_items_{name}", title=f"Sandbox items: {name}")


def _sandbox_status(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """The pack's one sentence on what the sandbox report is, as its own section.

    Written where no live sandbox observed the run — none ran, or the report is
    a recorded fixture — and filed with the sandbox views, so the report and
    the console's dynamic tab say it where a reader looks for the behaviour.
    """
    statement = _text(data.get("statement"))
    if not statement:
        return
    section = acc.get("sandbox_status", "Sandbox", "text")
    section.text = _cut_text(statement, entry.id)
    acc.credit(section, entry)


# The section of the behaviour links (``analysis.behaviour_code``), and its
# columns that hold the sample's or the sandbox's own text: the report writes
# each of those as a code span (``renderers.markdown``).
BEHAVIOUR_CODE_SECTION = "behaviour_code_links"
BEHAVIOUR_CODE_COLUMNS = ["Observed", "Value", "Sandbox items", "Held at", "Match", "Function"]
BEHAVIOUR_CODE_SAMPLE_COLUMNS = (1, 3)
# The platform's own words a "Held at" cell holds where no place holds the value.
BEHAVIOUR_CODE_PLAIN_WORDS = (behaviour_code.OBSERVED_ONLY, behaviour_code.PARTLY_READ)


def _behaviour_code(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """Each value the sandbox observed, one row per static place that holds it, or observed only.

    The text above the rows says what was compared, how much of each answer,
    and where the functions came from or why none could be stated.
    """
    links = [row for row in data.get("links") or [] if isinstance(row, dict)]
    table = acc.get(
        BEHAVIOUR_CODE_SECTION,
        "Observed behaviour linked to code",
        "table",
        columns=list(BEHAVIOUR_CODE_COLUMNS),
    )
    functions = data.get("functions")
    compared = [row for row in data.get("compared") or [] if isinstance(row, dict)]
    read = ", ".join(behaviour_code.compared_words(row) for row in compared)
    only = _text(data.get("observed_only_label")) or behaviour_code.OBSERVED_ONLY
    said = [
        f"{data.get('observed', 0)} values the sandbox observed, compared exactly (after the "
        f"platform's normalisation for each kind) with the texts of {read or 'no static answer'}: "
        f"{data.get('held', 0)} held, {data.get('observed_only', 0)} {only}."
    ]
    if isinstance(functions, dict):
        said.append(f"Functions from [{functions.get('entry')}] {functions.get('tool')}.")
    else:
        said.append(f"Functions: {functions}.")
    for key, reason in (data.get("absent") or {}).items():
        said.append(f"{key}: {reason}.")
    said.extend(f"{one[:1].upper()}{one[1:]}." for one in behaviour_code.unread_words(data))
    table.text = _cut_text(" ".join(said), entry.id)
    for row in links:
        kind, value = _text(row.get("kind")), _text(row.get("value"))
        items = ", ".join(str(item) for item in row.get("items") or [])
        if row.get("attribution") == behaviour_code.NOT_ATTRIBUTED:
            items += f" ({behaviour_code.NOT_ATTRIBUTED})"
        held = [h for h in row.get("held") or [] if isinstance(h, dict)]
        if not held:
            acc.add_row(table, [kind, value, items, only, "", ""])
            continue
        for holding in held:
            details = behaviour_code.place_details(holding)
            place = f"[{holding.get('entry')}] {behaviour_code.place_words(holding)}"
            if details:
                place += f" ({', '.join(details)})"
            how = _text(holding.get("matched")) or behaviour_code.EXACT
            if how != behaviour_code.EXACT:
                # The text that held the value, beside the place: it is not the value.
                place += f": {_text(holding.get('text'))}"
            acc.add_row(
                table,
                [
                    kind,
                    value,
                    items,
                    place,
                    how,
                    behaviour_code.function_words(holding, functions),
                ],
            )
    acc.credit(table, entry)


def _pcap(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    summary = data.get("summary")
    if not summary:
        return
    section = acc.get("pcap_summary", "Capture summary", "text")
    section.text = _cut_text(str(summary), entry.id)
    acc.credit(section, entry)


# Reverse-engineering tools name a function and answer about it, and list
# functions. The report does not paste decompilation, but which functions an
# analyst actually looked at is the one durable fact of a reverser's loop: an
# entry whose tool declares a function's code (``decompile``,
# ``function_disassembly``) or a function listing (``function_list``,
# ``method_list``) lands under "Functions examined", from any server
# (``CONSUMER_KINDS``). A batch of decompiled functions, or any answer listing
# several functions' code, lands there one line per function
# (``tool_kinds.function_parts``).
_FUNCTION_CONSUMERS = ("ledger_report._FUNCTION_TOOLS", "ledger_report._FUNCTION_LIST_TOOLS")


# What a function's line says when the conversation had no room for the answer.
FUNCTION_NOT_SHOWN = "answer not shown: no room left in the conversation"


def _called_address(entry: LedgerEntry) -> str:
    """The address a call gave in the argument its tool declares for one, or ``""``.

    ``arguments`` is read without a kind (``kind_free_facts``); an entry read
    by the legacy tables gives the shared address names only, as it always did.
    """
    facts = None if tool_kinds.read_by_name(entry) else tool_kinds.kind_free_facts(entry)
    for name in address_arguments(facts, tuple(entry.args)):
        value = entry.args.get(name)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return f"0x{value:x}"
        if isinstance(value, str) and value.strip():
            return value.strip()[:120]
    return ""


def _functions_examined(
    acc: _Sections, entry: LedgerEntry, _data: Any, seen: set[str] | None = None
) -> None:
    """One line for the function an entry examined, or for each function a batch listed.

    ``seen`` holds the functions already listed, in one spelling
    (``core.undeclared_tools.function_key``): a batch's function listed by
    another line, a single call's or another batch's, is not listed twice. A
    batch's answer cut for storage says so on its last line.
    """
    section = acc.get("functions_examined", "Functions examined", "list")
    parts = tool_kinds.function_parts(entry)
    if parts:
        _batch_functions(acc, section, entry, parts, seen)
        acc.credit(section, entry)
        return
    label = entry.symbol or _called_address(entry)
    if not label:
        # No argument of the call holds an address: the item says only that,
        # never the tool's own name twice.
        label = (
            "function listing"
            if tool_kinds.is_of(entry, "ledger_report._FUNCTION_LIST_TOOLS")
            else "no address in the call"
        )
    if answer_not_shown(entry):
        acc.add_item(section, f"{label} ({entry.tool}; {FUNCTION_NOT_SHOWN})")
    else:
        acc.add_item(section, f"{label} ({entry.tool})")
    acc.credit(section, entry)


def _batch_functions(
    acc: _Sections,
    section: EvidenceSection,
    entry: LedgerEntry,
    parts: list[Any],
    seen: set[str] | None,
) -> None:
    """The lines of the functions a batch's answer listed, each function once."""
    from maljan.core.undeclared_tools import ANSWER_CUT_NOTE, function_key

    cut = entry.truncated or any(part.cut or part.answer_cut for part in parts)
    named: list[str] = []
    for part in parts:
        key = function_key(part.where)
        if seen is not None:
            if key in seen:
                continue
            seen.add(key)
        named.append(part.where)
    if cut and not named:
        # Every function it listed is listed already; the cut is still said.
        named.append(parts[-1].where)
    for at, where in enumerate(named, start=1):
        said = [entry.tool]
        if answer_not_shown(entry):
            said.append(FUNCTION_NOT_SHOWN)
        if cut and at == len(named):
            said.append(ANSWER_CUT_NOTE)
        acc.add_item(section, f"{where} ({'; '.join(said)})")


def _finding_confidence(value: Any) -> str:
    """A finding's confidence as the analyst stated it, or that it stated none."""
    return f"{float(value):.2f}" if isinstance(value, int | float) else "not given"


def _reputation(acc: _Sections, entry: LedgerEntry, data: dict[str, Any]) -> None:
    """A reputation lookup, with the engine counts as rows of their own.

    The service answers the counts nested inside its payload, and the generic
    block flattens that into one cell a reader has to scroll to; the count is
    the one fact of the lookup a report states. The counts are the record the
    lookup's declaration read from the answer when the entry was written
    (``core.reputation``), from any server.
    """
    _generic_kv(acc, entry, data)
    answer = reputation_of(entry)
    if answer is None:
        return
    section = acc.get(f"tool_{entry.tool}", tool_kinds.section_title(entry), "kv")
    for name in ("malicious", "suspicious", "undetected", "harmless"):
        if name in answer.stats:
            acc.add_row(section, [f"engines {name}", str(answer.stats[name])])
    if answer.engines is not None:
        acc.add_row(section, ["engines", str(answer.engines)])


# The purpose-built section builders, by name. Which one draws an entry is
# its tool's declared kind (``BUILDER_OF_KIND``), from any server; an entry
# with no recorded source is drawn as its tool's name always drew it
# (``tool_kinds.builder_of``).
_BUILDERS: dict[str, Any] = {
    builder.__name__: builder
    for builder in (
        _identity,
        _signing,
        _binary_info,
        _strings,
        _iocs,
        _yara,
        _sigma,
        _capa,
        _sandbox_processes,
        _sandbox_network,
        _sandbox_signatures,
        _sandbox_dropped,
        _sandbox_registry,
        _sandbox_apis,
        _sandbox_mutexes,
        _sandbox_services,
        _sandbox_section,
        _sandbox_items,
        _sandbox_status,
        _behaviour_code,
        _pcap,
        _reputation,
    )
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
        title or tool_kinds.section_title(entry),
        "table",
        columns=columns,
    )
    for column in columns:
        if column not in section.columns:
            section.columns.append(column)
    declared = _declares_code(entry)
    for row in dicts:
        values = [row.get(column) for column in section.columns]
        acc.add_row(
            section,
            [
                _code_or_text(value, values[:at] + values[at + 1 :], declared)
                for at, value in enumerate(values)
            ],
        )
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
        title or tool_kinds.section_title(entry),
        "kv",
        columns=["Field", "Value"],
    )
    ours = our_own_words(data)
    declared = _declares_code(entry)
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
        acc.add_row(
            section,
            [str(name).replace("_", " "), _code_or_text(value, (name,), declared)],
        )
    acc.credit(section, entry)


def _generic_text(acc: _Sections, entry: LedgerEntry) -> None:
    if not entry.output.strip():
        return
    section = acc.get(f"tool_{entry.tool}", tool_kinds.section_title(entry), "text")
    if not section.text:
        section.text = _cut_text(entry.output, entry.id)
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
            section = acc.get(f"tool_{entry.tool}", tool_kinds.section_title(entry), "list")
            for item in data:
                acc.add_item(section, _text(item))
            acc.credit(section, entry)
        return
    _generic_text(acc, entry)


# ---------------------------------------------------------------------------
# Agent-contributed sections
# ---------------------------------------------------------------------------


def _artifact_sections(acc: _Sections, isrs: dict[str, Any]) -> None:
    """The tables the analysts established, grouped by the kind they named.

    A kind more than one artifact listed rows under is one table whose first
    columns say which analyst listed each row and the evidence that row's
    artifact cites (``LISTED_BY_COLUMN``, ``EVIDENCE_COLUMN``), so a merged
    table never loses whose row is whose or which ids stand behind it. Its
    columns are the union of what its rows hold: a cell past them adds its
    heading (:func:`_in_the_union`), so no cell is dropped or left unheaded.
    """
    by_kind: dict[str, list[tuple[str, Any]]] = {}
    for agent, isr in (isrs or {}).items():
        for artifact in list(getattr(isr, "artifacts", None) or []):
            kind = (getattr(artifact, "kind", "") or "artifact").strip() or "artifact"
            source = str(getattr(artifact, "source", "") or agent)
            by_kind.setdefault(kind, []).append((source, artifact))
    for kind, listed in by_kind.items():
        merged = len(listed) > 1
        shaped: list[tuple[str, Any, list[Any], list[str]]] = []
        for source, artifact in listed:
            rows = list(getattr(artifact, "rows", None) or [])
            columns = [str(c) for c in getattr(artifact, "columns", None) or []] or ["Value"]
            if not rows:
                label = getattr(artifact, "label", "") or kind
                rows = [[label, getattr(artifact, "value", "")]]
                columns = ["Label", "Value"]
            shaped.append((source, artifact, rows, columns))
        # A merged table is headed as its first artifact is (as it always was);
        # a later artifact headed otherwise has each row read by its own
        # headings and written in the table's layout (:func:`_placed`).
        headings = shaped[0][3]
        for source, artifact, rows, columns in shaped:
            section = acc.get(
                f"artifact_{kind}",
                kind.replace("_", " ").capitalize(),
                "table",
                columns=[LISTED_BY_COLUMN, EVIDENCE_COLUMN, *headings] if merged else columns,
            )
            _listed_by(section, source)
            cited = ", ".join(str(i) for i in getattr(artifact, "evidence_ids", None) or [])
            for row in rows:
                cells = [_text(cell) for cell in row]
                names: list[str] = []
                if merged:
                    cells, names = _placed(cells, columns, headings)
                full, added = _in_the_union(
                    section.columns,
                    [_text(source), cited, *cells] if merged else cells,
                    2 + len(headings) if merged else 0,
                    names,
                )
                held = len(section.rows)
                acc.add_row(section, full)
                if len(section.rows) > held:
                    section.columns.extend(added)
            for entry_id in getattr(artifact, "evidence_ids", None) or []:
                acc.cite(section, str(entry_id))


def _heading_keys(columns: list[str]) -> list[tuple[str, int]]:
    """Each heading as one key: its folded spelling, and which of that spelling it is."""
    counted: dict[str, int] = {}
    keys: list[tuple[str, int]] = []
    for column in columns:
        folded = column.strip().lower()
        keys.append((folded, counted.get(folded, 0)))
        counted[folded] = counted.get(folded, 0) + 1
    return keys


def _roles(columns: list[str]) -> tuple[int, int, int | None] | None:
    """The type, value and payload places of a listing: by its headings, else by position."""
    from maljan.reporting.ledger_projection import listed_columns

    named = listed_columns(columns)
    if named is not None:
        typed, valued, payload = named
        return typed, valued, payload if payload is not None and payload < len(columns) else None
    if len(columns) < 2:
        return None
    return 0, 1, 2 if len(columns) > 2 else None


def _placed(
    cells: list[str], columns: list[str], headings: list[str]
) -> tuple[list[str], list[str]]:
    """One artifact's row, read by its own ``columns``, in a table headed ``headings``.

    A row of an artifact headed as the table is kept as it is, and so is one
    where either side names no type and value (read by position, as it was).
    Otherwise its type, value and payload go where the table's headings put
    them, any other cell under the heading of its own spelling, and what the
    table has no place for follows the table's columns, the payload first:
    the place a reader takes a payload from when the headings name none.

    Returned with the artifact's own heading of each cell past ``headings``,
    ``""`` where it has none, for the table to head that cell by.
    """

    def own(at: int | None) -> str:
        return columns[at] if at is not None and 0 <= at < len(columns) else ""

    if _heading_keys(columns) == _heading_keys(headings):
        return cells, [own(at) for at in range(len(headings), len(cells))]
    mine, table = _roles(columns), _roles(headings)
    if mine is None or table is None:
        return cells, [own(at) for at in range(len(headings), len(cells))]
    placed: dict[int, int] = {mine[0]: table[0], mine[1]: table[1]}
    if mine[2] is not None and table[2] is not None:
        placed[mine[2]] = table[2]
    taken = set(placed.values())
    places = {key: at for at, key in enumerate(_heading_keys(headings))}
    for at, key in enumerate(_heading_keys(columns)):
        if at not in placed and places.get(key) is not None and places[key] not in taken:
            placed[at] = places[key]
            taken.add(places[key])
    out = [""] * len(headings)
    rest: list[str] = []
    names: list[str] = []
    for at, cell in enumerate(cells):
        if at in placed:
            out[placed[at]] = cell
        elif at != mine[2]:
            rest.append(cell)
            names.append(own(at))
    if table[2] is None and (rest or (mine[2] is not None and mine[2] not in placed)):
        payload = cells[mine[2]] if mine[2] is not None and mine[2] < len(cells) else ""
        rest = [payload if mine[2] not in placed else "", *rest]
        # The payload stays where a reader takes it from, whatever its heading.
        names = ["", *names]
    return out + rest, names


def _in_the_union(
    columns: list[str], row: list[str], first: int, names: list[str]
) -> tuple[list[str], list[str]]:
    """``row`` laid out in a table headed ``columns``, and the headings it adds.

    The cells from position ``first`` on are the ones the table's own headings
    have no place for, ``names`` their artifact's headings. A named cell goes
    under the column of its own heading, which it adds when the table has none;
    a cell with no heading of its own (the payload :func:`_placed` puts first
    among them is given none) stays at its position, as a reader takes the
    payload by position. An empty named cell says nothing and is not placed.

    The row is laid out by position instead when the named layout would be
    read otherwise (``ledger_projection.listed_cells``: a type, a value and a
    payload each taken from where a reader takes them), so naming a column
    never moves what a reader of the table takes from it; and so it is when
    the named layout would not hold every value the positional layout holds.
    """
    from maljan.reporting.ledger_projection import listed_cells, listed_columns

    positional = _laid_out(columns, row, first, [])
    if not any(name.strip() for name in names):
        return positional
    named = _laid_out(columns, row, first, names)

    def read(layout: tuple[list[str], list[str]]) -> list[str] | None:
        cells, added = layout
        if not cells:
            return None
        headed = [*columns, *added]
        listed = listed_headings_of(headed)
        return listed_cells(cells[len(headed) - len(listed) :], listed_columns(listed))

    def held(layout: tuple[list[str], list[str]]) -> Counter[str]:
        return Counter(cell for cell in layout[0] if cell)

    kept = named[0] and held(named) == held(positional) and read(named) == read(positional)
    return named if kept else positional


def _laid_out(
    columns: list[str], row: list[str], first: int, names: list[str]
) -> tuple[list[str], list[str]]:
    """:func:`_in_the_union`'s layout of ``row`` by ``names``: ``([], [])`` when two cells collide.

    A heading the table gains is kept only when the table is read as it was
    read with it (``ledger_projection.listed_columns``: a heading that names a
    type, a value or a payload moves where a reader takes them from);
    otherwise the column is headed ``Column N``, its position, or ``Payload``,
    which a reader takes the first cell past a type and a value as anyway.
    """
    from maljan.reporting.ledger_projection import listed_columns

    headed = list(columns)
    out = list(row[:first])
    end = len(out)

    def place(at: int, cell: str) -> bool:
        nonlocal end
        out.extend([""] * (at + 1 - len(out)))
        if out[at]:
            # A filled slot is never written over: an empty cell says nothing,
            # and a second value there is a collision.
            return not cell
        out[at] = cell
        end = max(end, at + 1)
        return True

    def add(own: str) -> int:
        reading = listed_columns(listed_headings_of(headed))
        taken = {str(c).strip().lower() for c in headed}
        heading = f"Column {len(headed) + 1}"
        for candidate in (own, heading, "Payload"):
            if (
                candidate
                and candidate.lower() not in taken
                and listed_columns(listed_headings_of([*headed, candidate])) == reading
            ):
                heading = candidate
                break
        headed.append(heading)
        return len(headed) - 1

    for k, cell in enumerate(row[first:]):
        own = names[k].strip() if k < len(names) else ""
        if not own:
            at = first + k
            while at >= len(headed):
                add("")
            if not place(at, cell):
                return [], []
            continue
        if not cell:
            continue
        free = [
            at
            for at in range(first, len(headed))
            if str(headed[at]).strip().lower() == own.lower() and not (at < len(out) and out[at])
        ]
        if not place(free[0] if free else add(own), cell):
            return [], []
    return out[:end], headed[len(columns) :]


# The first two columns of an artifact table more than one artifact listed rows in.
LISTED_BY_COLUMN = "Listed by"
EVIDENCE_COLUMN = "Evidence"

# The sources of an evidence section an analyst wrote: its tables, its findings.
ANALYST_SECTION_SOURCES = ("artifact:", "finding", "agent")


def listed_rows(section: Any) -> list[tuple[str, str, list[str]]]:
    """Each row of an artifact section, with the analyst who listed it and the ids it cites.

    Read from the ``Listed by`` and ``Evidence`` columns of a merged table, or
    from the section's one analyst and its ids otherwise. A merged table a
    report stored with only a ``Listed by`` column reads the section's ids.
    """
    analysts = listed_by(section)
    columns = [str(c) for c in getattr(section, "columns", None) or []]
    rows = [[str(cell) for cell in row] for row in getattr(section, "rows", None) or []]
    cited = ", ".join(str(i) for i in getattr(section, "evidence_ids", None) or [])
    if columns[:2] == [LISTED_BY_COLUMN, EVIDENCE_COLUMN]:
        return [(row[0], row[1], row[2:]) for row in rows if len(row) > 1]
    if columns[:1] == [LISTED_BY_COLUMN]:
        return [(row[0], cited, row[1:]) for row in rows if row]
    one = analysts[0] if analysts else ""
    return [(one, cited, row) for row in rows]


def listed_headings(section: Any) -> list[str]:
    """The headings of the cells :func:`listed_rows` gives each row of an artifact section."""
    return listed_headings_of([str(c) for c in getattr(section, "columns", None) or []])


def listed_headings_of(columns: list[str]) -> list[str]:
    """:func:`listed_headings` of a section headed ``columns``."""
    if columns[:2] == [LISTED_BY_COLUMN, EVIDENCE_COLUMN]:
        return columns[2:]
    if columns[:1] == [LISTED_BY_COLUMN]:
        return columns[1:]
    return columns


def artifact_sections(sections: Any) -> list[tuple[str, Any]]:
    """Each Appendix A section an analyst's artifact filled, with the kind it names."""
    return [
        (str(getattr(section, "key", "")).removeprefix("artifact_"), section)
        for section in sections or []
        if listed_by(section) and str(getattr(section, "key", "")).startswith("artifact_")
    ]


def analyst_persistence(sections: Any) -> list[dict[str, str]]:
    """The persistence the analysts listed, row by row, read from their Appendix A tables.

    ``kind``, ``target`` and ``payload`` under the headings that name them
    (``ledger_projection.listed_columns``), by position where the headings
    name none, as an analyst's persistence table is shaped, with the analyst
    that listed the row and the
    ids that row's artifact cites. Never read from ``MalwareReport.persistence``, which
    is the tools' and which the IOC table, the detection drafts, the
    corroboration corpus and the counts read; a stored report carries the same
    tables, so it reads the same rows.
    """
    from maljan.reporting.ledger_projection import listed_cells, listed_columns

    out: list[dict[str, str]] = []
    for kind, section in artifact_sections(sections):
        if kind.strip().lower() != "persistence":
            continue
        named = listed_columns(listed_headings(section))
        for analyst, cited, row in listed_rows(section):
            cells = [cell.strip() for cell in row]
            if not any(cells):
                continue
            cells = listed_cells(cells, named)
            out.append(
                {
                    "kind": cells[0] if len(cells) > 1 else "",
                    "target": cells[1] if len(cells) > 1 else cells[0],
                    "payload": cells[2] if len(cells) > 2 else "",
                    "listed_by": analyst,
                    "evidence": cited,
                }
            )
    return out


# What an artifact section's ``source`` starts with; the analysts who listed
# its rows follow, comma-separated.
ARTIFACT_SOURCE = "artifact:"


def _listed_by(section: Any, analyst: str) -> None:
    """Name ``analyst`` among the analysts whose rows an artifact section holds."""
    named = listed_by(section)
    if analyst and analyst not in named:
        named.append(analyst)
    section.source = ARTIFACT_SOURCE + ", ".join(named)


def listed_by(section: Any) -> list[str]:
    """The analysts whose rows an artifact section holds, or nothing for any other section."""
    source = str(getattr(section, "source", "") or "")
    if not source.startswith(ARTIFACT_SOURCE):
        return []
    return [name for name in source.removeprefix(ARTIFACT_SOURCE).split(", ") if name]


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
        # A word for "no technique" is printed as written and is no claim.
        if published is None or tid.upper() in published or says_no_technique(tid):
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
                    _finding_confidence(getattr(finding, "confidence", None)),
                    _text(getattr(finding, "evidence_ids", []) or []),
                ],
                sets=(0, 4),
                counted=acc.merges.finding,
            )
            for entry_id in getattr(finding, "evidence_ids", None) or []:
                acc.cite(section, str(entry_id))


def _agents_by_kind(ledger: list[LedgerEntry]) -> dict[str, list[str]]:
    """Each declared tool kind, with the agents whose calls of that kind answered, in order."""
    found: dict[str, dict[str, None]] = {}
    for entry in ledger:
        if not entry.ok or not entry.agent:
            continue
        kind = tool_kinds.kind_of(entry)
        if kind:
            found.setdefault(kind, {})[str(entry.agent)] = None
    return {kind: list(agents) for kind, agents in found.items()}


def _open_questions_section(
    acc: _Sections, isrs: dict[str, Any], ledger: list[LedgerEntry]
) -> None:
    """Every question an analyst left open, why, what would answer it and who could.

    "Who could answer" is read from the ledger, never guessed: the agents
    whose calls of the tool kind the question names answered in this run. A
    question that names no kind leaves the cell empty. Absent when no analyst
    left a question open, so a run without one renders as it did.
    """
    section: EvidenceSection | None = None
    by_kind: dict[str, list[str]] | None = None
    for agent, isr in (isrs or {}).items():
        for question in list(getattr(isr, "open_questions", None) or []):
            if section is None:
                section = acc.get(
                    "open_questions",
                    "Open questions",
                    "table",
                    columns=[
                        "Agent",
                        "Question",
                        "Why open",
                        "What would answer it",
                        "Who could answer",
                        "Evidence",
                    ],
                    source=OPEN_QUESTION_SOURCE,
                )
            kind = question.tool_kind.strip()
            if kind and by_kind is None:
                by_kind = _agents_by_kind(ledger)
            why = question.why_open
            acc.add_row(
                section,
                [
                    _text(question.source or agent),
                    _text(question.question),
                    _text(f"{why}: {question.detail}" if question.detail else why),
                    _text(would_answer_text(question)),
                    _text((by_kind or {}).get(kind, []) if kind else []),
                    _text(question.evidence_ids),
                ],
            )
            for entry_id in question.evidence_ids:
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
    from maljan.core.undeclared_tools import code_parts_read

    with code_parts_read():
        return _build_sections(ledger, isrs, file_type, platform, merges, published_techniques)


def _build_sections(
    ledger: list[LedgerEntry],
    isrs: dict[str, AgentISR] | None = None,
    file_type: str = "unknown",
    platform: str = "unknown",
    merges: MergeTally | None = None,
    published_techniques: frozenset[str] | None = None,
) -> list[EvidenceSection]:
    """:func:`build_sections`, each answer read once (``core.undeclared_tools.code_parts_read``)."""
    acc = _Sections(merges)

    identity = acc.get("identity", "Sample identity", "kv", columns=["Field", "Value"])
    identity.source = "routing"
    if file_type and file_type != "unknown":
        acc.add_row(identity, ["file type", file_type])
    if platform and platform != "unknown":
        acc.add_row(identity, ["platform", platform])

    seen = _singly_examined(ledger or [])
    for entry in ledger or []:
        if not entry.ok:
            # A failed call is on the record in the ledger and in the run
            # summary; it has no content to build a section out of.
            continue
        if any(tool_kinds.is_of(entry, consumer) for consumer in _FUNCTION_CONSUMERS):
            _functions_examined(acc, entry, entry.structured, seen)
            continue
        if tool_kinds.reads_code(entry, "ledger_report._FUNCTION_TOOLS"):
            # Code read as the kind a function's code is (a batch of decompiled
            # functions): its functions are examined ones, and its answer is
            # still drawn as it always was below.
            _functions_examined(acc, entry, entry.structured, seen)
        builder = _BUILDERS.get(tool_kinds.builder_of(entry) or "")
        data = entry.structured
        if builder is not None and isinstance(data, dict):
            if data.get("error"):
                continue
            builder(acc, entry, data)
            # A purpose-built section reads its kind's answer shape (or the
            # rows a rule tool declares). An operator's own tool of the kind
            # that answers in another shape is still in the report, as the
            # generic block, rather than drawn as nothing. An entry with no
            # source, or from a built-in source, is drawn as it always was.
            if tool_kinds.from_an_operator_source(entry) and not acc.credited(entry):
                _fallback(acc, entry)
            continue
        _fallback(acc, entry)

    _function_map_coverage(acc, ledger or [])
    _artifact_sections(acc, isrs or {})
    _findings_section(acc, isrs or {}, published_techniques)
    _open_questions_section(acc, isrs or {}, ledger or [])
    return acc.result()


def _singly_examined(ledger: list[LedgerEntry]) -> set[str]:
    """The functions a call of one function examined, in one spelling: a batch lists none again."""
    from maljan.core.undeclared_tools import function_key

    return {
        function_key(label)
        for entry in ledger
        if entry.ok
        and any(tool_kinds.is_of(entry, consumer) for consumer in _FUNCTION_CONSUMERS)
        and not tool_kinds.function_parts(entry)
        and (label := entry.symbol or _called_address(entry))
    }


def _function_map_coverage(acc: _Sections, ledger: list[LedgerEntry]) -> None:
    """One line under "Functions examined": functions visited against functions reaching artefacts.

    Read from the whole ledger the way the analysts' function map reads it
    (``agents.function_map``); absent when no function was visited.
    """
    from maljan.agents.function_map import build_function_map

    section = acc._by_key.get("functions_examined")
    if section is None:
        return
    try:
        found = build_function_map(ledger, None, [])
    except Exception:  # noqa: BLE001 — a line of the report never costs the section
        return
    if not found.visited:
        return
    line = f"Function map: {found.coverage()}."
    section.text = f"{section.text}\n\n{line}".strip() if section.text else line
