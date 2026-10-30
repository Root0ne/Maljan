"""The analyst report: what the sample is and does, in the order a reader acts on it.

The single-file report prints every measured table, every tool's answer, the
run's own bookkeeping and the model's prose side by side, and a reader looking
for what the sample does reads past all of it. This layout prints the same
report's findings in a fixed order — title block, executive summary,
introduction and scope, sample metadata, execution flow, functionality,
command and control, conclusion, detection, recommendations, the ATT&CK
table, limitations, and an appendix — and leaves the rest to the evidence
bundle (``renderers/bundle.py``), which prints every section of the
single-file report and links each citation to its entry.

What decides where a block goes is its kind, never a tool or a family: the
report model's prose, its configuration, command and channel tables, the
persistence and payload rows and the published techniques are findings and
print here; a tool's own table, a rule's hits, the process tree, the static
properties, the run's validation and coverage records, claims set aside and
every number a model put on its confidence print in the bundle.

A citation is not printed in the prose. Each group of evidence ids becomes a
numbered note (``[3]``) linking to the bundle's note of that number, which
lists the ids, each linked to its entry in the bundle's evidence index; each
section ends with a link to the bundle's sections behind it. The words of the
prose are printed as written, defanged, with only the citations moved.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from maljan.reporting.dedupe import distinct_processes
from maljan.reporting.defang import defang
from maljan.reporting.judge_reasons import judge_reasons_shown
from maljan.reporting.models import MalwareReport, TechnicalSubsection, outcome_words
from maljan.reporting.renderers.layout import BUNDLE_HTML, BUNDLE_JSON
from maljan.reporting.renderers.markdown import (
    _EV_RE,
    _NETWORK_KINDS,
    _PIPE,
    _code_span,
    _degraded_sentence,
    _divider,
    _encryption_table,
    _encrypts_files,
    _endpoint,
    _escape_block,
    _fenced,
    _finding_text,
    _header_facts,
    _inline_safe,
    _item,
    _left_out,
    _one_line,
    _paragraph_line,
    _ransomware_block,
    _reputation_line,
    _resolved_only,
    _row,
    _sample_check_line,
    _spawned,
    _states_ransomware,
    _step,
    _title_heading,
    _whole,
    confidence_word,
    is_carve_note,
    report_title,
)
from maljan.reporting.renderers.markdown import (
    _cell as _table_safe,
)

if TYPE_CHECKING:
    from maljan.reporting.renderers.markdown import MarkdownRenderer, _Context

# A run of citations written into prose: ``[ev_0004]``, ``[ev_0024][ev_0008]``,
# ``(ev_0021; ev_0025)``, each group with the space before it.
_CITATION_RUN = re.compile(
    r"(?:\s*[\[(]\s*ev_\d+(?:\s*[,;]\s*ev_\d+)*\s*[\])])+",
)
# A list of ids written bare beside other words: ``get_file_report, ev_0018, ev_0030``.
_BARE_IDS = re.compile(r"\bev_\d+(?:\s*,\s*ev_\d+)*\b")
# The numbering a model writes in front of a claim it quotes ("5. Routine …").
_CLAIM_NUMBER = re.compile(r"^\s*\d{1,3}\.\s+")
# Where a procedure's first sentence ends.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(\"'])")

# A value a statement names: an address, or a name with a capital, a digit or an
# underscore inside it (an API, a symbol, a token the sample compares). An
# evidence id is a citation, not a value.
_VALUE = re.compile(
    r"\b0x[0-9a-fA-F]+\b" + _PIPE + r"\b(?!ev_\d)[A-Za-z_][A-Za-z0-9_]*[A-Z0-9_][A-Za-z0-9_]*\b"
)
# The recorders of an indicator row that only observed it (``ConsolidatedIOC.source``):
# a capture or a strings pass. An unexported row of theirs, bound to no code and
# named by no model, is the bundle's; every other row stays in the table.
_OBSERVED_ONLY = frozenset({"sandbox", "strings"})
# Why a value only the report model's identifier table holds is not exported.
_IDENTIFIER_NOT_EXPORTED = (
    "not exported: the report model's identifier table publishes nothing itself"
)
# The entropy above which the single-file report flags a section [HIGH].
_HIGH_ENTROPY = 7.0
# Up to how many imports the metadata names one by one.
_IMPORTS_NAMED = 10
# How many values a statement must name that the report prints nowhere else.
_NEW_VALUES = 1
# The analyst layer a statement is labelled with ("static: …").
_LAYER_LABEL = re.compile(r"^\s*[\w.-]+:\s+")

# The anchor of a heading in the evidence bundle's HTML: its title without its
# number and voice tag, as the HTML renderer slugs it.
_SLUG = re.compile(r"[^a-z0-9]+")


def bundle_anchor(title: str) -> str:
    """The id the evidence bundle's HTML gives the heading titled ``title``."""
    slug = _SLUG.sub("-", title.lower()).strip("-")
    return f"sec-{slug or 'section'}"


def unique_anchor(anchor: str, taken: set[str]) -> str:
    """``anchor``, or the first of ``anchor-2``, ``anchor-3``… not in ``taken``; then taken.

    The one counter the bundle's HTML and its JSON number a repeated title by,
    so a section's anchor is the same in both.
    """
    unique, n = anchor, 2
    while unique in taken:
        unique, n = f"{anchor}-{n}", n + 1
    taken.add(unique)
    return unique


# Each section of this report, the sections of the evidence bundle that hold
# what it rests on, by the bundle heading's title.
_BEHIND: dict[str, tuple[str, ...]] = {
    "summary": ("Key findings", "Questions asked of this run"),
    "scope": ("Methodology", "Background"),
    "metadata": ("Sample overview", "Static properties"),
    "flow": ("Execution flow", "Observed behaviour"),
    "functionality": ("Technical analysis",),
    "c2": ("Command and control", "Configuration", "Commands and capabilities"),
    "conclusion": ("Verdict and assessment", "Attribution and related activity"),
    "detection": ("Indicators of compromise", "Detection"),
    "recommendations": ("Recommendations",),
    "attack": ("MITRE ATT&CK mapping",),
    "limitations": ("Limitations and analysis notes", "Run summary"),
    "appendix": ("Evidence index", "References"),
}

# The figures whose section this report prints; every other figure is drawn
# in the bundle, beside the section it illustrates there.
FIGURE_KINDS: frozenset[str] = frozenset({"infection_chain", "network_graph", "attack_matrix"})


@dataclass(frozen=True)
class CitationNote:
    """One numbered note: the evidence ids a passage of the analyst report rests on."""

    number: int
    evidence_ids: tuple[str, ...]
    section: str


@dataclass
class CitationNotes:
    """The notes of one render, numbered in the order the report cites them.

    The same set of ids cited twice is one note, cited twice.
    """

    ctx: _Context
    section: str = ""
    notes: list[CitationNote] = field(default_factory=list)
    _by_ids: dict[tuple[str, ...], CitationNote] = field(default_factory=dict)

    def marker(self, ids: Iterable[Any]) -> str:
        """The note marker for ``ids`` (``[3]``, linked), or ``""`` when there are none."""
        note = self._note(ids)
        if note is None:
            return ""
        # Set aside from the closing pass: a file name is no host to defang.
        return self.ctx.keep(f"[[{note.number}]]({BUNDLE_HTML}#cite-{note.number})")

    def linked(self, evidence_id: str) -> str:
        """One id the prose names as a word, kept, as a link to its note in the bundle."""
        note = self._note([evidence_id])
        if note is None:
            return evidence_id
        return self.ctx.keep(f"[{evidence_id}]({BUNDLE_HTML}#cite-{note.number})")

    def _note(self, ids: Iterable[Any]) -> CitationNote | None:
        key = tuple(dict.fromkeys(_one_line(i).strip() for i in ids if str(i).strip()))
        if not key:
            return None
        note = self._by_ids.get(key)
        if note is None:
            note = CitationNote(len(self.notes) + 1, key, self.section)
            self.notes.append(note)
            self._by_ids[key] = note
        return note

    def moved(self, text: str, ids: Iterable[Any] = ()) -> str:
        """``text`` with each citation written into it a note marker, and ``ids`` it does not
        cite as one more marker at its end."""
        cited: list[str] = []

        def note(found: re.Match[str]) -> str:
            group = _EV_RE.findall(found.group(0))
            cited.extend(group)
            return self.marker(group)

        text = _CITATION_RUN.sub(note, str(text or ""))

        def bare(found: re.Match[str]) -> str:
            group = _EV_RE.findall(found.group(0))
            cited.extend(group)
            if len(group) == 1:
                return self.linked(group[0])
            return self.marker(group)

        text = _BARE_IDS.sub(bare, text)
        rest = [i for i in ids if str(i).strip() and _one_line(i).strip() not in cited]
        if rest:
            text = text.rstrip() + self.marker(rest)
        return text


def analyst_sections(
    renderer: MarkdownRenderer, report: MalwareReport, ctx: _Context
) -> tuple[list[str], list[CitationNote]]:
    """The analyst report's sections in their fixed order, and the notes they cite."""
    layout = _Analyst(report, ctx)
    plan: list[tuple[str, Callable[[], str]]] = [
        ("title", layout.title),
        ("summary", layout.summary),
        ("scope", layout.scope),
        ("metadata", layout.metadata),
        ("flow", layout.flow),
        ("functionality", layout.functionality),
        ("c2", layout.c2),
        ("conclusion", layout.conclusion),
        ("detection", layout.detection),
        ("recommendations", layout.recommendations),
        ("attack", layout.attack),
        ("limitations", layout.limitations),
        ("appendix", layout.appendix),
    ]
    sections: list[str] = []
    for key, build in plan:
        layout.notes.section = key
        sections.append(renderer._safe_section(f"analyst_{key}", build))
        layout.written.append(sections[-1])
    return sections, list(layout.notes.notes)


def _heading(number: int, title: str) -> str:
    return f"## {number}. {_one_line(title)}"


def _subheading(number: str, title: str) -> str:
    return f"### {number} {_one_line(title)}"


def _behind(key: str, *, absent: tuple[str, ...] = ()) -> str:
    """The line a section ends with: the bundle's sections behind it, linked.

    Each title is one the bundle always prints (a numbered section or
    subsection prints a line when it has nothing); ``absent`` names one it
    does not print for this report.
    """
    links = ", ".join(
        f"[{title}]({BUNDLE_HTML}#{bundle_anchor(title)})"
        for title in _BEHIND.get(key, ())
        if title not in absent
    )
    return f"_In the evidence bundle: {links}._" if links else ""


def _first_sentence(text: str) -> str:
    """A claim's first sentence, without the number a model wrote in front of it."""
    body = _CLAIM_NUMBER.sub("", _one_line(text).strip())
    return _SENTENCE_END.split(body, maxsplit=1)[0].strip()


def _confidence_words(value: float | None) -> str:
    return confidence_word(value) if value is not None else ""


class _Analyst:
    """The sections of one analyst report, over one render's context."""

    def __init__(self, report: MalwareReport, ctx: _Context) -> None:
        self.report = report
        self.ctx = ctx
        self.notes = CitationNotes(ctx)
        self.ta = report.technical_analysis
        # What the sections before the one being written printed.
        self.written: list[str] = []

    # -- shared writing ---------------------------------------------------

    def _marked(self, text: str) -> str:
        """``text`` with the mark of each sentence a check left standing after it, as the
        single-file report marks it (``_Context.marked``).

        Each mark is set aside under a token, so neither the defanger nor the
        citation move reads it: a mark's own brackets are no citation.
        """
        claimed: list[tuple[int, int]] = []
        inserts: list[tuple[int, str]] = []
        for sentence, mark in self.ctx.flagged:
            start = text.find(sentence)
            while start != -1:
                end = start + len(sentence)
                inside = any(a <= start and end <= b for a, b in claimed)
                if not inside and not text.startswith(f" {mark}", end):
                    claimed.append((start, end))
                    inserts.append((end, mark))
                start = text.find(sentence, start + 1)
        for end, mark in sorted(inserts, reverse=True):
            # Kept from the closing pass, so made safe here as a cell makes it
            # (``_cell``): on one line, its separators escaped, so a mark in a
            # table cell cannot end the row or add a column.
            safe = _table_safe(_one_line(mark))
            text = f"{text[:end]} {self.ctx.keep(safe)}{text[end:]}"
        return text

    def _prose(self, text: str, ids: Iterable[Any] = ()) -> str:
        """Model prose as a paragraph: marked, defanged, its citations moved to note markers."""
        marked = self._marked(str(text or "").strip())
        return _escape_block(self.notes.moved(self.ctx.plain(marked), ids))

    def _line(self, text: Any, ids: Iterable[Any] = ()) -> str:
        """Model prose on one line, for an item, a step or a cell."""
        marked = self._marked(_one_line(text))
        return _one_line(self.notes.moved(self.ctx.plain(marked), ids))

    def _findings(self, rows: list[dict[str, str]]) -> list[str]:
        """The platform's unresolved findings on a section, one item each."""
        return [
            _item(f"_Unresolved:_ {_code_span(row['code'])}: {_finding_text(row, self.ctx.plain)}")
            for row in rows
        ]

    def _cell(self, text: Any) -> str:
        return self._line(text) if str(text or "").strip() else "-"

    def _verdict(self) -> str:
        report = self.report
        if report.verdict_not_assessed:
            return f"not assessed ({_one_line(report.verdict_not_assessed)})"
        said = _confidence_words(report.overall_confidence)
        return f"{_one_line(report.verdict)}" + (f" ({said})" if said else "")

    def _family(self) -> str:
        attr = self.report.attribution
        family = _one_line(attr.family)
        if not family or family.lower() == "unknown":
            return "none attributed"
        if attr.family_source == "sandbox":
            return f"{family} (named by the sandbox's classification)"
        said = _confidence_words(attr.family_confidence)
        family += f" ({said})" if said else ""
        # Grounded as the single-file report grounds it (``_family_words``):
        # the entries the judge cited, or that it cited none.
        if attr.family_evidence_ids:
            family += self.notes.marker(attr.family_evidence_ids)
        elif not attr.family_grounded:
            family += " (no evidence cited)"
        return family

    def _category(self) -> str:
        category = _one_line(self.report.malware_category).strip()
        return category if category and category.lower() != "unknown" else ""

    def _subsection(
        self, number: str, title: str, prose: list[TechnicalSubsection | None], body: list[str]
    ) -> list[str]:
        parts = [sub for sub in prose if sub is not None and sub.body.strip()]
        if not parts and not body:
            return []
        lines = [_subheading(number, title), ""]
        for sub in parts:
            lines.extend([self._prose(sub.body, sub.evidence_refs), ""])
        lines.extend(body)
        return [*lines, ""]

    # -- title block ------------------------------------------------------

    def title(self) -> str:
        report, ctx = self.report, self.ctx
        lines = [_title_heading(report_title(report)), ""]
        fm = report.front_matter
        if fm is not None:
            parts = [f"**TLP:{fm.tlp}**"]
            if fm.report_number:
                parts.append(f"Report {fm.report_number}")
            parts.append(fm.report_date or report.generated_at.date().isoformat())
            parts.append(f"{fm.publisher} {fm.product_type}")
            lines.append(" · ".join(parts) + "  ")
        else:
            lines.append(f"{report.generated_at.date().isoformat()}  ")
        severity = report.severity.rating if report.severity else "not assessed"
        facts = [f"**Verdict:** {self._verdict()}", f"**Severity:** {_one_line(severity)}"]
        facts.append(f"**Family:** {self._family()}")
        if self._category():
            facts.append(f"**Category:** {self._category()}{ctx.category_mark}")
        lines.append(" · ".join(facts) + "  ")
        ident = report.identity
        lines.append(
            f"**Sample:** {_code_span(ident.hashes.sha256 or 'unknown')} "
            f"({_inline_safe(ident.file_type, plain=ctx.plain)}, "
            f"{ident.file_size_bytes:,} bytes)"
        )
        for row in ctx.verdict_findings:
            lines.append(
                f"  \n_Unresolved on the verdict: {_code_span(row['code'])}: "
                f"{_one_line(_finding_text(row, ctx.plain))}_"
            )
        if report.verdict_not_assessed:
            lines.append(
                "\n> **[NO VERDICT]** No verdict was assessed: "
                f"{_one_line(report.verdict_not_assessed)}, so no judge ran."
            )
        elif report.overall_confidence is None:
            lines.append(
                "\n> **[NO CONFIDENCE ASSESSED]** The judge assessed no confidence for this "
                "verdict, and none is substituted for one."
            )
        if report.degraded_mode:
            lines.append("\n> **[DEGRADED RUN]** " + _degraded_sentence(report, ctx))
        return "\n".join(lines)

    # -- 1. executive summary ----------------------------------------------

    def summary(self) -> str:
        report = self.report
        lines = [_heading(1, "Executive summary"), ""]
        for finding in report.key_findings:
            lines.append(_item(self._line(finding.text, finding.evidence_ids)))
        summary = report.executive_summary.strip()
        if summary:
            if report.key_findings:
                lines.append("")
            lines.append(self._prose(summary))
        if not summary and not report.key_findings:
            lines.append(
                "No summary was written in this run; the findings below are the platform's "
                "own record of what the run established."
            )
        if self.ctx.narrative_findings:
            lines.extend(["", *self._findings(self.ctx.narrative_findings)])
        verdict = [f"the verdict is {self._verdict()}"]
        family = self._family()
        verdict.append(
            f"the family is {family}" if family != "none attributed" else "no family is attributed"
        )
        if report.severity is not None:
            verdict.append(f"the severity is {_one_line(report.severity.rating).lower()}")
        lines.extend(["", f"**Assessment:** {'; '.join(verdict)}."])
        answers = list(getattr(report, "question_answers", None) or [])
        if answers:
            lines.extend(["", "### Questions asked of this run", ""])
            for number, answer in enumerate(answers, 1):
                asked = re.sub(r"(?=#)", "\\\\", self.ctx.inline(answer.question))
                said = f"**Q{number}. {asked}** — {outcome_words(answer.outcome)}"
                if answer.answer.strip():
                    said += ": " + self._line(answer.answer, answer.evidence_ids)
                lines.append(_item(said))
        # The questions section is printed only for a run asked some.
        absent = () if answers else ("Questions asked of this run",)
        return "\n".join([*lines, "", _behind("summary", absent=absent)])

    # -- 2. introduction and scope -----------------------------------------

    def scope(self) -> str:
        report, ctx = self.report, self.ctx
        ident = report.identity
        name = _code_span(ctx.plain(ident.file_name or ident.hashes.sha256 or "unknown"))
        summary = report.run_summary or {}
        profile = summary.get("profile") or {}
        analysts = [str(a) for a in profile.get("analysts") or []]
        team = f" ({len(analysts)} analyst{'s' if len(analysts) != 1 else ''})" if analysts else ""
        kind = _inline_safe(ident.file_type, plain=ctx.plain)
        said = (
            f"This report covers one file, {name} ({kind}, {ident.file_size_bytes:,} bytes), "
            "submitted for analysis and examined by an automated team of language-model "
            f"analysts{team} working over tool servers; a judge stated the "
            "verdict and a report model wrote the assessed prose. "
            + ctx.sandbox_sentence()
            + " A step or finding read from the code is marked assessed; one a sandbox watched "
            "is marked observed."
        )
        lines = [_heading(2, "Introduction and scope"), "", _paragraph_line(said)]
        background = report.intro_background.strip()
        if background:
            lines.extend(["", "### Context", "", self._prose(background)])
        return "\n".join([*lines, "", _behind("scope")])

    # -- 3. sample metadata ------------------------------------------------

    def metadata(self) -> str:
        report, ctx = self.report, self.ctx
        ident = report.identity
        header = _header_facts(report)
        lines = [_heading(3, "Sample metadata"), "", _row("Field", "Value"), _divider(2)]
        lines.append(_row("File name", _code_span(ctx.plain(ident.file_name or "unknown"))))
        lines.append(_row("Size", f"{ident.file_size_bytes:,} bytes"))
        kind = ident.file_type
        if header["architecture"]:
            kind += f", {header['architecture']}"
        if header["is_dll"] is not None:
            kind += ", DLL" if header["is_dll"] else ", executable"
        lines.append(_row("Type", kind))
        if header["is_dll"] and (ident.file_name or "").lower().endswith(".exe"):
            lines.append(_row("Name and type", "a DLL submitted under an .exe name"))
        if header["compile_timestamp"]:
            lines.append(_row("Compile timestamp", f"{header['compile_timestamp']} (header value)"))
        if header["export_name"]:
            lines.append(_row("Export name", _code_span(ctx.plain(str(header["export_name"])))))
        if ident.internal_name:
            lines.append(_row("Internal name", _code_span(ctx.plain(str(ident.internal_name)))))
        signing = ident.signing
        signed = "yes" if signing.is_signed else "no"
        if signing.signer_subject:
            signed += f", {signing.signer_subject}"
        lines.append(_row("Signed", signed + self.notes.marker([signing.evidence_id or ""])))
        reputation = _reputation_line(report)
        if reputation:
            lines.append(_row("Reputation", self.notes.moved(ctx.plain(reputation))))
        static = report.static
        if static is not None and (static.packer_matches or static.packer_hint):
            names = ", ".join(str(m.get("name") or "not recorded") for m in static.packer_matches)
            lines.append(_row("Packer signatures", names or static.packer_hint))
        for algo, value in (
            ("MD5", ident.hashes.md5),
            ("SHA-1", ident.hashes.sha1),
            ("SHA-256", ident.hashes.sha256),
            ("imphash", ident.hashes.imphash),
            ("ssdeep", ident.hashes.ssdeep),
            ("TLSH", ident.hashes.tlsh),
        ):
            if value:
                lines.append(_row(algo, _code_span(str(value))))
        listed = [*self._sections(), *self._imports(), *self._exports()]
        if listed:
            lines.extend(["", *listed])
        return "\n".join([*lines, "", _behind("metadata")])

    def _sections(self) -> list[str]:
        """The file's sections on one line, each with its entropy; the table is the bundle's."""
        static = self.report.static
        if static is None or not static.sections:
            return []
        rows = list(
            dict.fromkeys(
                (s.name, s.virtual_address, s.raw_offset, s.entropy) for s in static.sections
            )
        )
        shown = ", ".join(
            f"{_code_span(self.ctx.plain(_one_line(name)))} {entropy:.2f}"
            + (" (high entropy)" if entropy > _HIGH_ENTROPY else "")
            for name, _, _, entropy in rows
        )
        return [f"Sections ({len(rows)}), with entropy: {shown}."]

    def _imports(self) -> list[str]:
        """How many functions the file imports from how many libraries; their names when few."""
        static = self.report.static
        if static is None or not static.imports:
            return []
        rows = list(dict.fromkeys((row.dll, row.function) for row in static.imports))
        libraries = {str(dll).lower() for dll, _ in rows if dll}
        said = (
            f"Imports: {len(rows)} function{'s' if len(rows) != 1 else ''} from "
            f"{len(libraries)} librar{'y' if len(libraries) == 1 else 'ies'}"
        )
        if len(rows) <= _IMPORTS_NAMED:
            said += ": " + ", ".join(
                _code_span(self.ctx.plain(f"{dll}!{function}" if dll else str(function)))
                for dll, function in rows
            )
        return [said + "."]

    def _exports(self) -> list[str]:
        static = self.report.static
        if static is None:
            return []
        rows = list(dict.fromkeys((e.name, e.ordinal, e.rva) for e in static.export_rows))
        names = [str(name or "(unnamed)") for name, _, _ in rows] or list(
            dict.fromkeys(str(n) for n in static.exports)
        )
        if not names:
            return []
        shown = ", ".join(_code_span(self.ctx.plain(n)) for n in names[:12])
        more = f" and {len(names) - 12} more" if len(names) > 12 else ""
        said = f"Exports ({len(names)}): {shown}{more}."
        rvas = [rva for _, _, rva in rows if rva]
        if len(rvas) > 1 and len(set(rvas)) == 1:
            said += f" All {len(rvas)} exports share one address, {_one_line(rvas[0])}."
        return [said]

    # -- 4. execution flow -------------------------------------------------

    def flow(self) -> str:
        steps = list(self.ta.execution_flow) if self.ta is not None else []
        lines = [_heading(4, "Execution flow"), ""]
        if not steps:
            lines.append("The report model wrote no execution flow in this run.")
        for index, step in enumerate(sorted(steps, key=lambda s: s.order), start=1):
            mark = "observed" if step.voice == "observed" else "assessed"
            # The platform's note beside a step, as the single-file report prints it.
            if str(step.order) in self.ctx.flow_findings:
                note = " _(unresolved: report.flow_voice)_"
            elif step.voice == "observed" and not self.ctx.sandbox_observed:
                note = " _(unresolved: report.flow_voice; no sandbox observation in this run)_"
            else:
                note = ""
            said = f"{self._line(step.action, step.evidence_refs)} _({mark})_{note}"
            lines.append(_step(index, said))
        return "\n".join([*lines, "", _behind("flow")])

    # -- 5. functionality --------------------------------------------------

    def functionality(self) -> str:
        report, ctx, ta = self.report, self.ctx, self.ta
        blocks: list[str] = []
        number = iter(range(1, 100))

        def numbered() -> str:
            return f"5.{next(number)}"

        if report.capabilities_narrative:
            body = [self._prose(p) + "\n" for p in report.capabilities_narrative if p.strip()]
            blocks.extend(self._subsection(numbered(), "Overview", [], body))
        cipher: list[str] = []
        enc = ta.encryption_scheme if ta is not None else None
        if enc is not None and not _encrypts_files(enc):
            cipher = self._encryption(enc)
        prose = [ta.packing_obfuscation, ta.evasion_antiforensics] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or cipher:
            blocks.extend(
                self._subsection(
                    numbered(), "Packing, obfuscation and anti-analysis", prose, cipher
                )
            )
        if ta is not None and ta.string_resolution is not None:
            blocks.extend(
                self._subsection(
                    numbered(), "API and string resolution", [ta.string_resolution], []
                )
            )
        persistence = self._persistence()
        prose = [ta.persistence_detail] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or persistence:
            blocks.extend(self._subsection(numbered(), "Persistence", prose, persistence))
        commands = self._commands_started()
        prose = [ta.discovery] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or commands:
            blocks.extend(self._subsection(numbered(), "Discovery", prose, commands))
        payloads = self._payloads()
        prose = [ta.payloads] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or payloads:
            blocks.extend(
                self._subsection(numbered(), "Payloads and dropped files", prose, payloads)
            )
        if ta is not None:
            family = _ransomware_block(ta, ctx, ransomware=_states_ransomware(report))
            if family:
                head, _, rest = family.partition("\n")
                title = head.split(" · ", 1)[0].removeprefix("### 5.9 ")
                blocks.extend([_subheading(numbered(), title), self.notes.moved(rest), ""])
        lines = [_heading(5, "Functionality"), ""]
        lines.extend(blocks or ["The report model described no capability in this run.", ""])
        return "\n".join([*lines, _behind("functionality")])

    def _encryption(self, enc: Any) -> list[str]:
        table = _encryption_table(enc, self.ctx)
        if not table:
            return []
        # The table's own evidence row is its last; the citation is the note.
        rows = table[2:-1]
        cited = self.notes.marker([enc.evidence_ref or ""])
        return ["Encryption scheme" + cited + ":", "", *rows, ""]

    def _persistence(self) -> list[str]:
        report, ctx = self.report, self.ctx
        if not report.persistence:
            return []
        lines = [_row("Kind", "Target", "Payload", "Technique"), _divider(4)]
        for mech in report.persistence[:40]:
            lines.append(
                _row(
                    mech.kind,
                    _code_span(_whole(ctx.plain(mech.target)))
                    + self.notes.marker([mech.evidence_ref or ""]),
                    _code_span(_whole(ctx.plain(mech.payload))) if mech.payload else "-",
                    mech.technique_id or "-",
                )
            )
        lines.extend(_left_out(len(report.persistence), 40, "persistence mechanisms"))
        return [*lines, ""]

    def _commands_started(self) -> list[str]:
        dynamic = self.report.dynamic
        commands = [
            node
            for node in _spawned(distinct_processes(dynamic.process_tree if dynamic else []))
            if node.command_line
        ]
        if not commands:
            return []
        lines = ["Commands the sample started _(observed)_:", "", _row("PID", "Command line")]
        lines.append(_divider(2))
        for node in commands[:20]:
            lines.append(_row(node.pid, _code_span(_whole(self.ctx.plain(node.command_line)))))
        lines.extend(_left_out(len(commands), 20, "commands"))
        return [*lines, ""]

    def _payloads(self) -> list[str]:
        report, ctx = self.report, self.ctx
        static, dynamic = report.static, report.dynamic
        carved = [r for r in (static.embedded_resources if static else []) if r.get("carved")]
        dropped = [
            op
            for op in (dynamic.file_operations if dynamic else [])
            if isinstance(op, dict) and op.get("operation") == "write"
        ]
        if not carved and not dropped:
            return []
        lines = [_row("Name/offset", "Size", "SHA-256", "How found"), _divider(4)]
        for res in carved[:10]:
            size = res.get("size")
            lines.append(
                _row(
                    _code_span(ctx.plain(str(res.get("id") or "not recorded"))),
                    f"{size} bytes" if isinstance(size, int) and size > 0 else "not recorded",
                    _code_span(str(res.get("sha256")).lower()) if res.get("sha256") else "-",
                    "carved from the file",
                )
            )
        for op in dropped[:20]:
            named = str(op.get("path") or op.get("name") or "not recorded")
            lines.append(
                _row(
                    _code_span(_whole(ctx.plain(named))),
                    f"{op['size']} bytes" if op.get("size") else "not recorded",
                    _code_span(str(op.get("sha256")).lower()) if op.get("sha256") else "-",
                    "dropped while a sandbox watched",
                )
            )
        lines.extend(_left_out(len(carved), 10, "carved payloads"))
        lines.extend(_left_out(len(dropped), 20, "dropped files"))
        notes = [r for r in (static.embedded_resources if static else []) if is_carve_note(r)]
        if notes:
            lines.extend(
                ["", *(_item(_inline_safe(str(r["type"]), plain=ctx.plain)) for r in notes)]
            )
        return [*lines, ""]

    # -- 6. command and control --------------------------------------------

    def c2(self) -> str:
        ctx, ta = self.ctx, self.ta
        blocks: list[str] = []
        prose = [ta.command_and_control, ta.message_packet_structure] if ta else []
        protocol = self._channels() + self._requests()
        if any(sub is not None and sub.body.strip() for sub in prose) or protocol:
            blocks.extend(self._subsection("6.1", "Protocol and endpoints", prose, protocol))
        if ta is not None and ta.configuration:
            body = [_row("Key", "Value", "How obtained"), _divider(3)]
            for index, item in enumerate(ta.configuration, start=1):
                # The platform's marks, as the single-file report prints them:
                # the IOC table's state of each value, an uncited row, a value
                # none of its cited entries holds whole.
                how: str = item.how_obtained
                if index in ctx.config_findings:
                    how += " (unresolved: report.configuration_uncited)"
                if index in ctx.config_unheld:
                    how += " (unresolved: report.value_not_in_cited_entry)"
                body.append(
                    _row(
                        self._cell(item.key),
                        self._line(item.value, item.evidence_refs) + ctx.publish_state(item.value),
                        how,
                    )
                )
            blocks.extend([_subheading("6.2", "Configuration"), "", *body, ""])
        if ta is not None and (ta.commands or ta.cli_flags):
            body = []
            if ta.commands:
                body.extend([_row("ID", "Command", "Description"), _divider(3)])
                for cmd in ta.commands:
                    body.append(
                        _row(
                            self._cell(cmd.id or "-"),
                            self._cell(cmd.name),
                            self._line(cmd.description or "-", cmd.evidence_refs),
                        )
                    )
                body.append("")
            if ta.cli_flags:
                body.extend(["Command-line flags:", "", _row("Flag", "Meaning"), _divider(2)])
                for flag in ta.cli_flags:
                    body.append(
                        _row(
                            _code_span(ctx.plain(flag.flag)),
                            self._line(flag.description or "-", [flag.evidence_ref or ""]),
                        )
                    )
                body.append("")
            blocks.extend([_subheading("6.3", "Commands"), "", *body])
        lines = [_heading(6, "Command and control"), ""]
        lines.extend(
            blocks
            or [
                "No command-and-control channel was described or observed in this run.",
                "",
            ]
        )
        return "\n".join([*lines, _behind("c2")])

    def _channels(self) -> list[str]:
        channels = self.report.c2_channels
        if not channels:
            return []
        lines = [
            _row("Channel", "Protocol", "Endpoint(s)", "Encryption", "Message format"),
            _divider(5),
        ]
        for ch in channels:
            fmt = " / ".join(part for part in (ch.beacon_format, ch.packet_layout) if part)
            refs = list(ch.evidence_refs) + ([ch.evidence_ref] if ch.evidence_ref else [])
            lines.append(
                _row(
                    self._cell(ch.name) + self.notes.marker(refs),
                    self._cell(ch.protocol),
                    "; ".join(_endpoint(e) for e in ch.endpoints) or "-",
                    self._cell(ch.encryption),
                    self._cell(fmt),
                )
            )
        return [*lines, ""]

    def _requests(self) -> list[str]:
        net, ctx = self.report.network, self.ctx
        observed = [u for u in (net.urls if net else []) if u.source == "sandbox"]
        lines: list[str] = []
        if observed:
            lines.extend(["Requests _(observed)_:", "", _row("Method", "URL", "User-Agent")])
            lines.append(_divider(3))
            for u in observed[:20]:
                lines.append(
                    _row(
                        _inline_safe(u.method or "-", pipes=False, plain=ctx.plain),
                        _code_span(defang(_whole(u.url), "url")),
                        _inline_safe(_whole(u.user_agent or "-"), pipes=False, plain=ctx.plain),
                    )
                )
            lines.extend(_left_out(len(observed), 20, "requests"))
            lines.append("")
        if net is not None and (net.ja3_fingerprints or net.ja3s_fingerprints):
            prints = [f"JA3 {_code_span(_one_line(j))}" for j in net.ja3_fingerprints]
            prints += [f"JA3S {_code_span(_one_line(j))}" for j in net.ja3s_fingerprints]
            lines.extend(["TLS fingerprints _(observed)_: " + ", ".join(prints) + ".", ""])
        return lines

    # -- 7. conclusion -----------------------------------------------------

    def conclusion(self) -> str:
        report = self.report
        lines = [_heading(7, "Conclusion"), ""]
        said = f"The sample is assessed as {self._verdict()}"
        if self._category():
            said += f", a {self._category()}"
        family = self._family()
        said += (
            f", attributed to the family {family}"
            if family != "none attributed"
            else ", with no family attributed"
        )
        severity = report.severity
        if severity is not None:
            said += f", at {_one_line(severity.rating).lower()} severity"
        lines.append(_paragraph_line(said + "."))
        if severity is not None and severity.business_impact.strip():
            lines.extend(["", self._prose(severity.business_impact)])
        if severity is not None and severity.likely_targets:
            targets = ", ".join(_one_line(t) for t in severity.likely_targets)
            lines.extend(["", f"Likely targets: {targets}."])
        stored = report.conclusion
        if stored is not None and stored.sophistication_rating:
            lines.extend(["", f"Sophistication: {_one_line(stored.sophistication_rating)}."])
        if stored is not None and stored.text.strip():
            lines.extend(["", self._prose(stored.text)])
        if self.ctx.verdict_findings:
            lines.extend(["", *self._findings(self.ctx.verdict_findings)])
        return "\n".join([*lines, "", _behind("conclusion")])

    # -- 8. detection ------------------------------------------------------

    def detection(self) -> str:
        lines = [_heading(8, "Detection"), ""]
        lines.extend(self._indicators())
        lines.extend(self._rules())
        hunting = [rec for rec in self.report.defensive_recommendations if rec.detection]
        if hunting:
            lines.extend(["### 8.3 Hunting guidance", ""])
            lines.extend(
                _item(
                    self._line(rec.detection)
                    + (f" ({_one_line(rec.technique_id)})" if rec.technique_id else "")
                )
                for rec in hunting
            )
            lines.append("")
        return "\n".join([*lines, _behind("detection")])

    def _indicators(self) -> list[str]:
        """The indicator table: every row of the IOC table but an unexported observation.

        A value the run does not export that only an observation pass recorded
        — a name or an address a capture or a strings pass saw, bound to no
        code and named by no model — is counted here and listed in the
        bundle's indicator section with the reason. Every other row is printed,
        with what recovered it and the publish rule's answer where it does not
        export the value.
        """
        from maljan.reporting.renderers.stix_renderer import publishes

        report, ctx = self.report, self.ctx
        rows: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        recorded = 0
        for ioc in ctx.iocs:
            exported = publishes(ioc.published)
            if not exported and str(ioc.source or "") in _OBSERVED_ONLY:
                recorded += 1
                continue
            seen.add(ioc.value.strip().lower())
            value = (
                defang(ioc.value, ioc.kind or "")
                if ioc.kind in _NETWORK_KINDS
                else ctx.plain(ioc.value)
            )
            role = "; ".join(
                part
                for part in (
                    ctx.inline(ioc.context) if ioc.context else "",
                    f"recovered by {ctx.inline(ioc.recovered_by)}" if ioc.recovered_by else "",
                )
                if part
            )
            if not exported:
                answer = ctx.plain(_one_line(ioc.published or "")).strip() or "not exported"
                role += f" _({_inline_safe(answer, pipes=False, plain=ctx.plain)})_"
            rows.append((ioc.type, value, role or "-"))
        identifiers = list(self.ta.host_identifiers) if self.ta is not None else []
        for index, item in enumerate(identifiers, start=1):
            if item.value.strip().lower() in seen:
                continue
            seen.add(item.value.strip().lower())
            role = self._line(item.purpose, item.evidence_refs) if item.purpose.strip() else "-"
            # The marks the single-file report prints beside the row.
            if index in ctx.identifier_findings:
                role += " (unresolved: report.identifier_uncited)"
            if index in ctx.identifier_unheld:
                role += " (unresolved: report.value_not_in_cited_entry)"
            state = ctx.publish_state(item.value).strip()
            role += f" _({_IDENTIFIER_NOT_EXPORTED}" + (f"; {state[1:-1]}" if state else "") + ")_"
            rows.append((self._cell(item.kind), ctx.plain(_one_line(item.value)), role))
        lines = ["### 8.1 Indicators of compromise", ""]
        if not rows:
            lines.extend(["No indicator was extracted in this run.", ""])
        else:
            lines.extend([_row("Type", "Value", "Role"), _divider(3)])
            for kind, value, role in rows:
                lines.append(_row(kind, _code_span(value), role))
            lines.append("")
        if recorded:
            lines.extend(
                [
                    f"{recorded} further value{'s' if recorded != 1 else ''} only a capture or a "
                    f"strings pass recorded {'are' if recorded != 1 else 'is'} not exported; the "
                    "bundle lists each with the reason.",
                    "",
                ]
            )
        rid = _one_line((report.run_summary or {}).get("report_id") or "{report_id}")
        lines.extend(
            [
                "Network values are defanged for reading. A value with the publish rule's answer "
                "beside it is not in the machine-readable outputs, which carry the exported "
                "values live: the STIX 2.1 "
                f"bundle ({_code_span(f'/reports/{rid}/stix')}), the indicator list "
                f"({_code_span(f'/reports/{rid}/iocs')}) and the MISP attributes of the JSON "
                f"report ({_code_span(f'/reports/{rid}/full')}).",
                "",
            ]
        )
        return lines

    def _rules(self) -> list[str]:
        """Each drafted rule by name and what checking it against the sample found.

        A rule a file engine ran against the sample prints its body in the
        appendix only where it matched; one no engine runs on a file (a
        behaviour or traffic rule) prints its body there too. A rule that did
        not match, or did not compile, is named here and printed in the bundle.
        """
        from maljan.reporting.renderers.markdown import _RULE_SECTIONS

        matched = [s for s in self.report.sections if s.key in _RULE_SECTIONS]
        rules = self.report.detection_signatures
        if not rules and not matched:
            return []
        lines = ["### 8.2 Detection rules", ""]
        # The rules that matched the sample, by name, as the single-file report
        # names them; their rows are the bundle's.
        for section in matched:
            at = section.columns.index("Rule") if "Rule" in section.columns else 0
            every = [_one_line(row[at]) for row in section.rows if len(row) > at]
            names = ", ".join(_code_span(self.ctx.plain(n)) for n in every[:20]) or "none"
            more = f" and {len(every) - 20} more (in the bundle)" if len(every) > 20 else ""
            title = _one_line(section.title)
            lines.append(
                _item(
                    f"Matched the sample, {title}: {names}{more}"
                    + self.notes.marker(section.evidence_ids)
                )
            )
        if matched and rules:
            lines.append("")
        for rule in rules:
            kind = _one_line(rule.kind).upper()
            status = "does not compile" if rule.compile_error else "compiles"
            said = f"**{kind}** {_code_span(_one_line(rule.name))} — {status}"
            checked = _sample_check_line(rule, self.ctx)
            if checked:
                said += f". {checked}"
            lines.append(_item(said + ("" if self._printed(rule) else " Printed in the bundle.")))
        if any(self._printed(rule) for rule in rules):
            lines.extend(
                ["", "The rule bodies are in the appendix. Test a rule before deploying it."]
            )
        return [*lines, ""]

    @staticmethod
    def _printed(rule: Any) -> bool:
        if rule.compile_error:
            return False
        return rule.matches_sample is not False

    # -- 9. recommendations ------------------------------------------------

    def recommendations(self) -> str:
        recs = self.report.defensive_recommendations
        lines = [_heading(9, "Recommendations"), ""]
        if not recs:
            lines.append("The report model gave no recommendation in this run.")
        else:
            lines.extend([_row("Priority", "Category", "Action", "Rationale", "Technique")])
            lines.append(_divider(5))
            order = {"P0": 0, "P1": 1, "P2": 2}
            for rec in sorted(recs, key=lambda r: order.get(r.priority, 9)):
                lines.append(
                    _row(
                        rec.priority,
                        rec.category.replace("_", " "),
                        self._line(rec.action),
                        self._line(rec.rationale),
                        rec.technique_id or "-",
                    )
                )
        return "\n".join([*lines, "", _behind("recommendations")])

    # -- 10. ATT&CK --------------------------------------------------------

    def attack(self) -> str:
        from maljan.reporting.renderers.markdown import _is_mbc_id, _tactic_key

        report = self.report
        lines = [_heading(10, "MITRE ATT&CK mapping"), ""]
        mappings = {m.technique_id: m for m in report.ttp_mappings}
        rows: list[str] = []
        seen: set[str] = set()
        held: list[str] = []
        for cell in sorted(report.capability_matrix, key=_tactic_key):
            if _is_mbc_id(cell.technique_id) or cell.technique_id in seen:
                continue
            seen.add(cell.technique_id)
            if cell.not_published or not cell.technique_id_valid:
                held.append(self._held(cell))
                continue
            claim = str(cell.evidence[0]) if cell.evidence else ""
            tactic = cell.tactic_name or cell.tactic or "-"
            rows.append(
                _row(
                    _one_line(tactic),
                    cell.technique_id,
                    _one_line(cell.technique_name),
                    self._procedure(claim, _EV_RE.findall(" ".join(map(str, cell.evidence))))
                    + self._status(cell.technique_id, cell.note),
                )
            )
        for tid, mapping in mappings.items():
            if tid in seen:
                continue
            seen.add(tid)
            claim = str(mapping.evidence_quotes[0]) if mapping.evidence_quotes else ""
            rows.append(
                _row(
                    _one_line(mapping.tactic_name or mapping.tactic or "-"),
                    tid,
                    _one_line(mapping.technique_name),
                    self._procedure(claim, _EV_RE.findall(" ".join(mapping.evidence_quotes)))
                    + self._status(tid, ""),
                )
            )
        if rows:
            lines.extend([_row("Tactic", "ID", "Technique", "Procedure"), _divider(4), *rows])
        else:
            lines.append("No ATT&CK technique is published in this run.")
        if held:
            lines.extend(
                [
                    "",
                    f"{len(held)} further technique{'s were' if len(held) != 1 else ' was'} named "
                    "and not published, each with the reason (the claims behind each are in the "
                    "bundle):",
                    "",
                    *held,
                ]
            )
        return "\n".join([*lines, "", _behind("attack")])

    def _held(self, cell: Any) -> str:
        """A technique named and not published, with the status the single-file report gives it."""
        from maljan.reporting.judge_reasons import JUDGE_REASON_WIDTH, status_shown
        from maljan.schemas.isr_models import UNVERIFIED_TECHNIQUE_MARKER

        if not cell.technique_id_valid:
            status = f"unverified id ({UNVERIFIED_TECHNIQUE_MARKER})"
        else:
            status = "claimed, not published: " + status_shown(
                cell.not_published, JUDGE_REASON_WIDTH, self.ctx.plain
            )
        return _item(
            f"{cell.technique_id} {_one_line(cell.technique_name)}: {status}"
            + self._status(cell.technique_id, "")
        )

    def _status(self, technique_id: str, note: str) -> str:
        """What the single-file report says beside a published row's status, or ``""``.

        How little a rule match stands behind a technique only a rule matched,
        the row's own note, and the platform's unresolved findings about it.
        """
        from maljan.reporting.renderers.markdown import (
            _TECHNIQUE_FINDING_CODES,
            _finding_technique,
        )

        said: list[str] = []
        rule_only = self.ctx.rule_only.get(technique_id)
        if rule_only:
            said.append(self.ctx.plain(_one_line(rule_only)))
        if note:
            said.append(self.ctx.plain(judge_reasons_shown(note)[0]))
        codes = [
            str(row.get("code"))
            for row in self.ctx.unresolved
            if str(row.get("code", "")).startswith(_TECHNIQUE_FINDING_CODES)
            and _finding_technique(row) == technique_id.upper()
        ]
        if codes:
            said.append("unresolved: " + ", ".join(dict.fromkeys(codes)))
        return f" _({'; '.join(said)})_" if said else ""

    def _procedure(self, claim: str, ids: list[str]) -> str:
        sentence = _first_sentence(_CITATION_RUN.sub("", claim))
        if not sentence:
            return "-" + self.notes.marker(ids)
        return self._line(sentence, ids)

    # -- 11. limitations ---------------------------------------------------

    def limitations(self) -> str:
        report, ctx = self.report, self.ctx
        said: list[str] = []
        if report.verdict_not_assessed:
            said.append(f"No verdict was assessed: {_one_line(report.verdict_not_assessed)}.")
        if report.degraded_mode:
            said.append(_degraded_sentence(report, ctx))
        partial = ctx.partial_sentence().strip()
        if partial:
            said.append(partial)
        count = len(report.degradation_reasons)
        if count:
            said.append(
                f"The run recorded {count} limitation{'s' if count != 1 else ''}, each with its "
                "reason and remedy in the bundle."
            )
        if not ctx.sandbox_observed:
            said.append(
                "Without a sandbox observation, what the sample does is read from its code and "
                "was not watched running."
            )
        undiscussed = len(getattr(report, "claims_not_discussed", None) or [])
        if undiscussed:
            said.append(
                f"{undiscussed} analyst claim{'s' if undiscussed != 1 else ''} in force "
                f"{'are' if undiscussed != 1 else 'is'} not discussed in this report and "
                f"{'are' if undiscussed != 1 else 'is'} printed whole in the bundle."
            )
        if not said:
            said.append("The run recorded no limitation.")
        lines = [_heading(11, "Limitations"), "", _paragraph_line(" ".join(said))]
        return "\n".join([*lines, "", _behind("limitations")])

    # -- appendix ----------------------------------------------------------

    def _statements(self) -> list[str]:
        """The analysts' statements of the ATT&CK section's rule-matched techniques that add a
        value: each fact once, so one whose values the report already prints is left out."""
        from maljan.reporting.renderers.markdown import _is_mbc_id, _tactic_key

        report = self.report
        hits = list(report.static.api_technique_hits) if report.static else []
        by_tid: dict[str, list[dict[str, Any]]] = {}
        for hit in hits:
            by_tid.setdefault(str(hit.get("technique_id") or ""), []).append(hit)
        have = set(_VALUE.findall("\n".join(self.written)))
        out: list[str] = []
        for cell in sorted(report.capability_matrix, key=_tactic_key):
            rules = by_tid.get(cell.technique_id) or []
            if _is_mbc_id(cell.technique_id) or not rules:
                continue
            # The statements the single-file report prints are these techniques'
            # only (``_resolved_only_lines``); every other cell's statements are
            # stored and printed nowhere, so the report gains no text here that
            # the single-file report did not print.
            if not all(_resolved_only(hit) for hit in rules):
                continue
            for statement in cell.statements:
                text = _LAYER_LABEL.sub("", str(statement), count=1)
                new = [v for v in dict.fromkeys(_VALUE.findall(text)) if v not in have]
                if len(new) < _NEW_VALUES:
                    continue
                have.update(new)
                out.append(
                    _item(
                        f"{cell.technique_id} {_one_line(cell.technique_name)}: {self._line(text)}"
                    )
                )
        return out

    def appendix(self) -> str:
        report = self.report
        lines = ["## Appendix", ""]
        printed = [rule for rule in report.detection_signatures if self._printed(rule)]
        if printed:
            lines.extend(["### Detection rules", ""])
            lines.append(
                "_Drafted from templates over this report's own values and not reviewed by an "
                "analyst. Each body is printed as written, its network values not defanged, so "
                "it compiles as deployed._"
            )
            lines.append("")
            for rule in printed:
                kind = _one_line(rule.kind).upper()
                lines.extend([f"**{kind}** {_code_span(_one_line(rule.name))}", ""])
                fence = rule.kind if rule.kind in {"yara", "sigma"} else ""
                fenced = _fenced(rule.body.rstrip(), fence)
                fenced[1] = self.ctx.keep(fenced[1])
                lines.extend([*fenced, ""])
        statements = self._statements()
        if statements:
            lines.extend(["### Analyst statements that add detail", ""])
            lines.append(
                "_What the analysts wrote naming a technique a rule matched only on names "
                "resolved at runtime, where a statement names a value this report prints "
                "nowhere else. Every statement is in the bundle._"
            )
            lines.extend(["", *statements, ""])
        if report.references:
            lines.extend(["### References", ""])
            for ref in report.references:
                note = f" — {ref.note}" if ref.note else ""
                lines.append(_item(f"[{ref.source}]({ref.url}){note}"))
            lines.append("")
        bundle = self.ctx.keep(f"[{BUNDLE_HTML}]({BUNDLE_HTML}) and [{BUNDLE_JSON}]({BUNDLE_JSON})")
        lines.extend(
            [
                "### Evidence bundle",
                "",
                _paragraph_line(
                    "What this report does not print is in the evidence bundle beside it ("
                    + bundle
                    + "): the observed behaviour and the static properties, the full ATT&CK and "
                    "indicator tables, the analysts' statements, every tool call with its output, "
                    "the run's limitations and its summary. Each numbered note above links to the "
                    "evidence entries it rests on there."
                ),
            ]
        )
        return "\n".join(lines)
