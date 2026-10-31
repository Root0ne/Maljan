"""What the analyst report asks of the composer: its own sections, its style and its channels.

The analyst report (``renderers/analyst.py``) reads like a professional malware
report: a short executive summary of the key capabilities, the findings in a
fixed order, a conclusion of a few paragraphs, one scoped limitations
paragraph and an ATT&CK table with one sentence of procedure per technique.
This module holds what the composer (``reporting.composer``) needs for it:

* four sections the composer writes beside the technical spine, with the
  object each answers with and the evidence each is shown
  (:func:`analyst_bundle`): the summary's capability bullets, the conclusion,
  the limitations paragraph and the procedure of each published technique.
  Each reads only what the report held before the composer ran, as every
  section does, so the sections still run at once;
* the style every section's prose is held to (:func:`style_violations`): no
  confidence written as a number and no word of how the report was made. A
  finding is shown to the model once and, if the sentence stays, marked where
  it stands; the words are never rewritten;
* the shape of the four sections (:func:`summary_shape_violations` and the
  rest): at most eight bullets, two or three paragraphs of conclusion, one
  paragraph of limitations, one sentence per published technique;
* the channel check (:func:`channel_binding_violations`): a value a channel
  row gives — an endpoint, a quoted verb — is held in the run's entries
  beside the code that uses it, and a row naming other code is asked about;
* the analyst statements only the ATT&CK section holds
  (:func:`statements_to_fold`), given to the functionality and
  command-and-control sections so each fact is written where it belongs.

Every rule reads the report's own fields and the entries' text, never a tool's
or a family's name.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from maljan.analysis.technique_ids import is_technique_id
from maljan.memory.attck_loader import TACTIC_ID_RE
from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import (
    CHANNEL_BINDING_CODE,
    NUMERIC_CONFIDENCE_CODE,
    PROCESS_WORDS_CODE,
    PROSE_SHAPE_CODE,
    VALUE_NOT_CARRIED_CODE,
    EntryTexts,
    Violation,
    image_bases_in,
)
from maljan.reporting.models import CapabilityBullet, MalwareReport, TechniqueProcedure

# ---------------------------------------------------------------------------
# The four sections and the objects they answer with
# ---------------------------------------------------------------------------


class SummaryOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    bullets: list[CapabilityBullet] = Field(default_factory=list)


class ConclusionOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    body: str = Field("")
    evidence_refs: list[str] = Field(default_factory=list)


class LimitationsOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    body: str = Field("")
    evidence_refs: list[str] = Field(default_factory=list)


class ProceduresOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    procedures: list[TechniqueProcedure] = Field(default_factory=list)


# The sections, in the order the composer asks for them after the spine.
ANALYST_SECTIONS: dict[str, type[BaseModel]] = {
    "summary": SummaryOut,
    "conclusion": ConclusionOut,
    "limitations": LimitationsOut,
    "attack_procedures": ProceduresOut,
}

# How many capability bullets the executive summary holds, and how many
# paragraphs the conclusion is.
MAX_SUMMARY_BULLETS = 8
CONCLUSION_PARAGRAPHS = (2, 3)
# How many sentences one summary bullet may run to: one line, its subject first.
_BULLET_SENTENCES = 2

# ---------------------------------------------------------------------------
# What each section is shown
# ---------------------------------------------------------------------------

# The heading the analyst statements a section folds in are shown under, as a
# label of each (``[T1234 statement]``).
STATEMENT_LABEL = "{technique} statement"
# The label of a key finding the summary is shown, and of the verdict's own
# rationale the conclusion is shown.
FINDING_LABEL = "summary finding {number}"
OVERVIEW_LABEL = "capability overview {number}"
PARAGRAPH_LABEL = "summary paragraph"
# How many of a published technique's claims its procedure is written from.
_PROCEDURE_CLAIMS = 2
RATIONALE_LABEL = "verdict rationale"


def _confidence_words(value: float | None) -> str:
    from maljan.reporting.renderers.markdown import confidence_word

    return confidence_word(value) if value is not None else ""


def _assessment_facts(report: MalwareReport) -> dict[str, Any]:
    """The verdict, the family and the severity, each confidence in words."""
    attr = report.attribution
    family = str(attr.family or "").strip()
    facts: dict[str, Any] = {
        "verdict": (
            f"not assessed ({report.verdict_not_assessed})"
            if report.verdict_not_assessed
            else report.verdict
        ),
        "verdict_confidence": _confidence_words(report.overall_confidence),
        "family": family if family.lower() not in ("", "unknown") else "",
        "family_confidence": _confidence_words(attr.family_confidence) if family else "",
        "category": report.malware_category if report.malware_category != "unknown" else "",
        "severity": report.severity.rating if report.severity else "",
    }
    return {key: value for key, value in facts.items() if value}


def _claim(text: str, refs: Sequence[Any] = (), label: str = "") -> dict[str, str]:
    return {
        "claim": str(text or ""),
        "evidence_ref": ", ".join(str(r) for r in refs if str(r).strip()),
        "agent": "",
        "label": label,
    }


def published_techniques(report: MalwareReport) -> dict[str, tuple[str, list[str], list[str]]]:
    """Each technique the ATT&CK table publishes: its name, its claims and the ids they cite.

    The same rows, in the same order, as the analyst report's table
    (``renderers.analyst._Analyst.attack``): a valid, published, non-MBC cell
    of the capability matrix, then a published mapping the matrix lacks.
    """
    from maljan.reporting.renderers.markdown import _EV_RE, _is_mbc_id, _tactic_key

    out: dict[str, tuple[str, list[str], list[str]]] = {}
    seen: set[str] = set()
    for cell in sorted(report.capability_matrix, key=_tactic_key):
        if _is_mbc_id(cell.technique_id) or cell.technique_id in seen:
            continue
        seen.add(cell.technique_id)
        if cell.not_published or not cell.technique_id_valid:
            continue
        claims = [str(c) for c in cell.evidence if str(c).strip()]
        out[cell.technique_id] = (
            cell.technique_name,
            claims,
            list(dict.fromkeys(_EV_RE.findall(" ".join(claims)))),
        )
    for mapping in report.ttp_mappings:
        tid = mapping.technique_id
        if not tid or tid in seen:
            continue
        seen.add(tid)
        claims = [str(q) for q in mapping.evidence_quotes if str(q).strip()]
        out[tid] = (
            mapping.technique_name,
            claims,
            list(dict.fromkeys(_EV_RE.findall(" ".join(claims)))),
        )
    return out


def _open_questions(report: MalwareReport) -> list[str]:
    """The questions the run left open, as its own table lists them."""
    for section in report.sections:
        if section.key != "open_questions" or "Question" not in section.columns:
            continue
        at = section.columns.index("Question")
        return list(dict.fromkeys(str(row[at]).strip() for row in section.rows if len(row) > at))
    return []


def analyst_bundle(
    section: str,
    report: MalwareReport,
    technical_evidence: Any = None,
    isr_reports: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The evidence one of :data:`ANALYST_SECTIONS` is shown, in a section bundle's shape.

    Each reads what the report held before the composer ran, and no more than
    it needs: the summary and the conclusion the key findings and the
    capability overview the narrative wrote, each citing its entries, with the
    verdict in words (and the verdict's rationale for the conclusion); the
    limitations the run's recorded limitations and open questions; the
    procedures the published techniques with their first claims. The claims in
    force are not shown again: the findings were written from them, and every
    claim beside them would put each of these calls over a price tier.
    """
    from maljan.reporting.evidence_bundles import binary_facts, sandbox_entry_ids

    binary = binary_facts(report)
    findings = [
        _claim(f.text, f.evidence_ids, FINDING_LABEL.format(number=n))
        for n, f in enumerate(report.key_findings, 1)
        if f.text.strip()
    ] + [
        _claim(p, (), OVERVIEW_LABEL.format(number=n))
        for n, p in enumerate(report.capabilities_narrative, 1)
        if str(p).strip()
    ]
    if report.executive_summary.strip():
        findings.insert(0, _claim(report.executive_summary, (), PARAGRAPH_LABEL))
    if section == "summary":
        return {
            "claims": findings,
            "tool_outputs": [],
            "binary": binary,
            "facts": _assessment_facts(report),
        }
    if section == "conclusion":
        facts = _assessment_facts(report)
        severity = report.severity
        if severity is not None and severity.business_impact.strip():
            facts["business_impact"] = severity.business_impact.strip()
        if severity is not None and severity.likely_targets:
            facts["likely_targets"] = list(severity.likely_targets)
        stored = report.conclusion
        rationale = (
            [_claim(stored.text, (), RATIONALE_LABEL)]
            if stored is not None and stored.text.strip()
            else []
        )
        return {
            "claims": [*rationale, *findings],
            "tool_outputs": [],
            "binary": binary,
            "facts": facts,
        }
    if section == "limitations":
        facts = {
            "limitations_recorded": list(report.degradation_reasons),
            "open_questions": _open_questions(report),
            # Said only when it is a limitation: a fact that is false is no gap.
            "no_sandbox_observation": not sandbox_entry_ids(report),
            "degraded_run": bool(report.degraded_mode),
            "verdict_not_assessed": report.verdict_not_assessed or "",
        }
        return {"claims": [], "tool_outputs": [], "binary": binary, "facts": facts}
    if section == "attack_procedures":
        published = published_techniques(report)
        technique_claims = [
            _claim(text, refs, tid)
            for tid, (_name, texts, refs) in published.items()
            for text in texts[:_PROCEDURE_CLAIMS]
        ]
        return {
            "claims": technique_claims,
            "tool_outputs": [],
            "binary": binary,
            "facts": {
                "published_techniques": [
                    f"{tid} {name}".strip() for tid, (name, _t, _r) in published.items()
                ]
            },
        }
    raise KeyError(section)


# The ATT&CK tactic a statement's technique sits under, and the section of the
# functionality or command-and-control part that owns its facts.
_TACTIC_SECTIONS: dict[str, str] = {
    "TA0003": "persistence_detail",
    "TA0004": "evasion_antiforensics",
    "TA0005": "evasion_antiforensics",
    "TA0007": "discovery",
    "TA0010": "command_and_control",
    "TA0011": "command_and_control",
}
# The section a statement whose tactic names none of the above is folded into.
_FOLD_DEFAULT = "payloads"
_LAYER_LABEL = re.compile(r"^\s*[\w.-]+:\s+")


def statements_to_fold(report: MalwareReport) -> dict[str, list[dict[str, str]]]:
    """The analyst statements only the ATT&CK section holds, by the section that owns them.

    The statements of a technique a rule matched only on names resolved at
    runtime (the ones the analyst report's appendix prints where they name a
    value printed nowhere else): each statement is given to one section, by its
    technique's tactic, so the section states its facts once, in their place.
    """
    from maljan.reporting.renderers.markdown import _is_mbc_id, _resolved_only, _tactic_key

    static = report.static
    hits = list(static.api_technique_hits) if static else []
    by_tid: dict[str, list[dict[str, Any]]] = {}
    for hit in hits:
        by_tid.setdefault(str(hit.get("technique_id") or ""), []).append(hit)
    out: dict[str, list[dict[str, str]]] = {}
    seen: set[str] = set()
    for cell in sorted(report.capability_matrix, key=_tactic_key):
        rules = by_tid.get(cell.technique_id) or []
        if _is_mbc_id(cell.technique_id) or not rules:
            continue
        if not all(_resolved_only(hit) for hit in rules):
            continue
        section = _TACTIC_SECTIONS.get(str(cell.tactic or "").upper(), _FOLD_DEFAULT)
        for statement in cell.statements:
            text = _LAYER_LABEL.sub("", str(statement), count=1).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.setdefault(section, []).append(
                _claim(text, (), STATEMENT_LABEL.format(technique=cell.technique_id))
            )
    return out


def code_around_values(report: MalwareReport) -> dict[str, list[str]]:
    """Each recovered network value and the functions the recovering tools name around it.

    Read from the report's record of what each recovering tool read and where
    (``EmulatedStrings.recovered_by``): the functions around the code that
    uses or decodes the text, as each tool named them — which of them uses it
    is the section's to read from the entries. A value no tool placed is left
    out.
    """
    record = report.emulated_strings
    if record is None:
        return {}
    out: dict[str, list[str]] = {}
    for value, rows in record.recovered_by.items():
        functions = list(dict.fromkeys(f for row in rows for f in row.functions if f))
        if functions:
            out[record.spelled.get(value, value)] = functions
    return out


# ---------------------------------------------------------------------------
# The style every section's prose is held to
# ---------------------------------------------------------------------------

# A confidence written as a number: beside the word ("confidence 0.85",
# "0.35 confidence", "85% confidence") or a bare one in parentheses ("(0.60)").
_A_CONFIDENCE = r"(?<![\w.])(?:0?\.\d{1,3}|1\.0{1,3}|\d{1,3}(?:\.\d+)?\s?%)(?![\w.]*\d)"
_NUMERIC_CONFIDENCE = re.compile(
    # The number attached to the word: "confidence 0.85", "confidence of 0.6",
    # "confidence: 85%", "(confidence 0.60)" ...
    r"\bconfidence\b\s*(?:(?:of|is|was|at|level|score)\s*)?[:=]?\s*\(?"
    + _A_CONFIDENCE
    # ... or the word attached to the number: "0.35 confidence", "85% confidence".
    + r"|"
    + _A_CONFIDENCE
    + r"\)?\s+(?:overall\s+)?confidence\b",
    re.IGNORECASE,
)
# The phrasings of how the report was produced, never of what the sample does:
# a word alone ("ledger", "producer", "model", "tool") is a sample's term as
# often, so only the phrasings that name the run's own record are read.
_PROCESS_WORDS = re.compile(
    r"\b(?:(?:the|this run's|the run's) ledger(?!\s+of\b)|ledger entr(?:y|ies)"
    r"|per the judge|the judge (?:kept|ruled|stated|said|found|accepted|rejected|dropped|named)"
    r"|tool calls?|claim numbers?|analyst claims?|language models?|report models?)\b",
    re.IGNORECASE,
)
# An agent's name is a process word where it is an identifier ("static_r2"):
# a name that is also an English word ("dynamic") is not told from one.
_DISTINCT_NAME = re.compile(r"[_\d]")
# The fields of an answer whose strings are the sample's values, not prose.
_VALUE_FIELDS = frozenset(
    {
        "value",
        "endpoints",
        "evidence_refs",
        "evidence_ref",
        "id",
        "key",
        "flag",
        "technique_id",
        "verbatim_content",
        "filename",
        "company_id_hash",
        "iv",
        "file_marker",
        "extension",
        "how_obtained",
        "voice",
        "kind",
    }
)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(\"'\[])")


def agent_names(report: MalwareReport) -> list[str]:
    """The run's analysts' names that are identifiers, as the run summary lists them."""
    profile = (report.run_summary or {}).get("profile") or {}
    names = [str(a) for a in profile.get("analysts") or [] if str(a).strip()]
    return [name for name in names if _DISTINCT_NAME.search(name)]


def _prose_strings(payload: Any, path: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """Every prose string of an answer with its path; the sample's values are left out."""
    if depth > 5:
        return
    if isinstance(payload, str):
        yield path, payload
    elif isinstance(payload, Mapping):
        for key, value in payload.items():
            if str(key) in _VALUE_FIELDS:
                continue
            yield from _prose_strings(value, f"{path}.{key}" if path else str(key), depth + 1)
    elif isinstance(payload, list | tuple):
        for index, value in enumerate(payload):
            yield from _prose_strings(value, f"{path}[{index}]", depth + 1)


def sentences(text: str) -> list[str]:
    """``text``'s sentences, each as written."""
    return [part.strip() for part in _SENTENCE_END.split(str(text or "").strip()) if part.strip()]


def _found_in(text: str, pattern: re.Pattern[str]) -> list[tuple[str, list[str]]]:
    """Each sentence of ``text`` that ``pattern`` finds something in, with what it found."""
    out: list[tuple[str, list[str]]] = []
    for sentence in sentences(text):
        found = [m.group(0).strip() for m in pattern.finditer(sentence)]
        if found:
            out.append((sentence, list(dict.fromkeys(found))))
    return out


def style_violations(
    payload: Any, names: Sequence[str] = (), evidence: str = ""
) -> list[Violation]:
    """The prose of an answer that writes a confidence as a number or names how it was made.

    One finding per field and kind, naming every sentence; each sentence is
    marked where it stands if it stays (``validation.MARKED_IN_PLACE``).
    ``names`` are the run's agents' identifier names (:func:`agent_names`);
    ``evidence`` is the text the section was shown: a phrasing it holds is the
    sample's or a tool's term there, and is not asked about.
    """
    if payload is None:
        return []
    process = _PROCESS_WORDS
    if names:
        process = re.compile(
            _PROCESS_WORDS.pattern
            + "|"
            + "|".join(rf"(?<![\w]){re.escape(name)}(?![\w])" for name in names),
            re.IGNORECASE,
        )
    out: list[Violation] = []
    for path, text in _prose_strings(payload):
        numbers = _found_in(text, _NUMERIC_CONFIDENCE)
        if numbers:
            said = ", ".join(dict.fromkeys(f for _s, found in numbers for f in found))
            out.append(
                Violation(
                    code=NUMERIC_CONFIDENCE_CODE,
                    message=(
                        f"{safe_finding_value(path)} writes a confidence as a number "
                        f"({safe_finding_value(said)}). Say how confident the assessment is in "
                        "words (high, moderate, low), never as a number."
                    ),
                    path=path,
                    quoted=tuple(s for s, _f in numbers),
                    labels=tuple(", ".join(f) for _s, f in numbers),
                )
            )
        shown = evidence.lower()
        words = [
            (sentence, kept)
            for sentence, found in _found_in(text, process)
            if (kept := [f for f in found if f.lower() not in shown])
        ]
        if words:
            said = ", ".join(dict.fromkeys(f for _s, found in words for f in found))
            out.append(
                Violation(
                    code=PROCESS_WORDS_CODE,
                    message=(
                        f"{safe_finding_value(path)} names how this report was made "
                        f"({safe_finding_value(said)}). State the finding itself, in the "
                        "sample's terms: no ledger, judge, mediator, producer, "
                        "model, agent or tool call, and no analyst's name or claim number."
                    ),
                    path=path,
                    quoted=tuple(s for s, _f in words),
                    labels=tuple(", ".join(f) for _s, f in words),
                )
            )
    return out


# ---------------------------------------------------------------------------
# The shape of the four sections
# ---------------------------------------------------------------------------


def _rows(payload: Any, key: str) -> list[Mapping[str, Any]]:
    rows = payload.get(key) if isinstance(payload, Mapping) else None
    return [row for row in rows or [] if isinstance(row, Mapping)]


def summary_shape_violations(payload: Any) -> list[Violation]:
    """A summary of more than eight bullets, or a bullet longer than one line."""
    bullets = [row for row in _rows(payload, "bullets") if str(row.get("text") or "").strip()]
    out: list[Violation] = []
    if len(bullets) > MAX_SUMMARY_BULLETS:
        out.append(
            Violation(
                code=PROSE_SHAPE_CODE,
                path="bullets",
                message=(
                    f"The summary has {len(bullets)} bullets; it holds at most "
                    f"{MAX_SUMMARY_BULLETS}. Keep the most actionable capabilities, one bullet "
                    "each, and leave the rest to the sections that describe them."
                ),
            )
        )
    for index, row in enumerate(bullets):
        if len(sentences(str(row.get("text") or ""))) > _BULLET_SENTENCES:
            number = index + 1
            out.append(
                Violation(
                    code=PROSE_SHAPE_CODE,
                    path=f"bullets[{index}].text",
                    message=(
                        f"Bullet {number} runs to more than {_BULLET_SENTENCES} sentences. "
                        "Write each capability on one line, its subject first."
                    ),
                )
            )
    return out


def _paragraphs(text: str) -> list[str]:
    return [p for p in re.split(r"\n\s*\n", str(text or "").strip()) if p.strip()]


def conclusion_shape_violations(payload: Any) -> list[Violation]:
    """A conclusion that is not two or three paragraphs."""
    body = str(payload.get("body") or "") if isinstance(payload, Mapping) else ""
    count = len(_paragraphs(body))
    low, high = CONCLUSION_PARAGRAPHS
    if not body.strip() or low <= count <= high:
        return []
    return [
        Violation(
            code=PROSE_SHAPE_CODE,
            path="body",
            message=(
                f"The conclusion is {count} paragraph{'s' if count != 1 else ''}; write "
                f"{low} or {high} short paragraphs, separated by a blank line."
            ),
        )
    ]


def limitations_shape_violations(payload: Any) -> list[Violation]:
    """Limitations written as more than one paragraph."""
    body = str(payload.get("body") or "") if isinstance(payload, Mapping) else ""
    count = len(_paragraphs(body))
    if count <= 1:
        return []
    return [
        Violation(
            code=PROSE_SHAPE_CODE,
            path="body",
            message=(
                f"The limitations are {count} paragraphs; write one short paragraph of "
                "scoped sentences."
            ),
        )
    ]


def procedure_violations(payload: Any, published: Sequence[str]) -> list[Violation]:
    """A procedure for a technique the report does not publish, or longer than one sentence."""
    known = {str(t).strip().upper() for t in published}
    out: list[Violation] = []
    for index, row in enumerate(_rows(payload, "procedures")):
        tid = str(row.get("technique_id") or "").strip().upper()
        if tid not in known:
            out.append(
                Violation(
                    code=PROSE_SHAPE_CODE,
                    path=f"procedures[{index}].technique_id",
                    message=(
                        f"{safe_finding_value(tid) or 'A procedure'} is not a technique this "
                        "report publishes; write a procedure only for a technique listed in the "
                        "evidence."
                    ),
                )
            )
        if len(sentences(str(row.get("procedure") or ""))) > 1:
            out.append(
                Violation(
                    code=PROSE_SHAPE_CODE,
                    path=f"procedures[{index}].procedure",
                    message=(
                        f"The procedure for {safe_finding_value(tid) or 'this technique'} is "
                        "more than one sentence; write one sentence saying how the sample "
                        "carries it out."
                    ),
                )
            )
    return out


# ---------------------------------------------------------------------------
# The channel check
# ---------------------------------------------------------------------------

_ADDRESS = re.compile(r"(?<![0-9A-Za-z_])0x([0-9a-f]{3,16})(?![0-9a-z_])", re.IGNORECASE)
_WHOLE_ADDRESS = re.compile(r"0x[0-9a-f]{3,16}", re.IGNORECASE)
_QUOTED = re.compile(r"\"([^\"\n]{2,80})\"")
# How far after a quoted value an address is the value's own place ('"X" string
# at 0x1f00'), not the code the row names.
_PLACE_AFTER = 40
# Above this an address is read with its image base folded out where none is known.
_LOW_ADDRESS = 0xFFFFFFFF
_ALIGNMENT = 0x10000
_CHANNEL_TEXT_FIELDS = ("name", "protocol", "encryption", "packet_layout", "beacon_format")


def _forms(address: int, bases: Sequence[int]) -> set[int]:
    forms = {address}
    forms.update(address - base for base in bases if address >= base)
    if not bases and address > _LOW_ADDRESS:
        forms.add(address % _ALIGNMENT)
    return forms


def _addresses_in(node: Any, *, deep: bool) -> list[str]:
    """The address strings ``node`` holds: its own fields, and every nested one when ``deep``."""
    found: list[str] = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _WHOLE_ADDRESS.fullmatch(item.strip()):
                found.append(item.strip())
        elif isinstance(item, Mapping):
            for value in item.values():
                if isinstance(value, str) or deep:
                    stack.append(value)
        elif isinstance(item, list | tuple) and (deep or item is node):
            stack.extend(item)
    return found


def _records_beside(node: Any, wanted: str) -> list[str]:
    """The addresses of each record of a JSON answer that holds ``wanted`` as a whole value.

    The record is the object that holds the value, with everything nested in
    it; where that object holds no address, the nearest object above it that
    holds one of its own (a row whose list of texts holds the value).
    """
    out: list[str] = []
    stack: list[tuple[Any, tuple[Mapping[str, Any], ...]]] = [(node, ())]
    while stack:
        item, above = stack.pop()
        if isinstance(item, Mapping):
            holds = any(isinstance(v, str) and v.strip().lower() == wanted for v in item.values())
            if holds:
                found = _addresses_in(item, deep=True)
                if not found:
                    for parent in reversed(above):
                        found = _addresses_in(parent, deep=False)
                        if found:
                            break
                out.extend(found)
            for value in item.values():
                if isinstance(value, Mapping | list):
                    stack.append((value, (*above, item)))
        elif isinstance(item, list):
            in_list = any(isinstance(v, str) and v.strip().lower() == wanted for v in item)
            if in_list:
                for parent in reversed(above):
                    found = _addresses_in(parent, deep=False)
                    if found:
                        out.extend(found)
                        break
            stack.extend((value, above) for value in item if isinstance(value, Mapping | list))
    return out


class _Beside:
    """What the run's entries hold beside each value: the code addresses of its records."""

    def __init__(self, entries: EntryTexts) -> None:
        self.entries = entries
        self.bases = image_bases_in(entries.entries.values())
        self._parsed: dict[str, Any] = {}
        self._held: dict[str, tuple[set[int], list[str], list[str]]] = {}

    def _json(self, entry_id: str) -> Any:
        if entry_id not in self._parsed:
            output = str(getattr(self.entries.entries.get(entry_id), "output", "") or "")
            parsed: Any = None
            if output.lstrip().startswith(("{", "[")):
                try:
                    parsed = json.loads(output)
                except (TypeError, ValueError):
                    parsed = None
            self._parsed[entry_id] = parsed
        return self._parsed[entry_id]

    def held(self, value: str) -> tuple[set[int], list[str], list[str]]:
        """The address forms beside ``value``, the addresses as written, and the entries."""
        key = value.strip().lower()
        if key not in self._held:
            forms: set[int] = set()
            written: list[str] = []
            holders: list[str] = []
            for entry_id in self.entries.holding(value):
                parsed = self._json(entry_id)
                if parsed is None:
                    continue
                found = _records_beside(parsed, key)
                if found:
                    holders.append(entry_id)
                for address in found:
                    written.append(address)
                    forms |= _forms(int(address, 16), self.bases)
            self._held[key] = (forms, list(dict.fromkeys(written)), holders)
        return self._held[key]


def _channel_code(channel: Mapping[str, Any]) -> tuple[list[int], dict[str, set[int]], list[str]]:
    """The addresses a channel row names, each quoted value's own place, and its quoted values."""
    text = " ".join(str(channel.get(f) or "") for f in _CHANNEL_TEXT_FIELDS)
    named = [int(m.group(1), 16) for m in _ADDRESS.finditer(text)]
    places: dict[str, set[int]] = {}
    quoted: list[str] = []
    for match in _QUOTED.finditer(text):
        value = match.group(1).strip()
        quoted.append(value)
        after = text[match.end() : match.end() + _PLACE_AFTER]
        places.setdefault(value.lower(), set()).update(
            int(m.group(1), 16) for m in _ADDRESS.finditer(after)
        )
    return named, places, list(dict.fromkeys(quoted))


def channel_binding_violations(payload: Any, entries: EntryTexts | None) -> list[Violation]:
    """Channel rows given a value the entries hold beside another row's code, or beside neither.

    Each row names the code its traffic runs through (its addresses). A value
    the row gives — a quoted verb or string, an endpoint — is looked for in the
    run's entries, and the code addresses of each record holding it are read
    (:class:`_Beside`). Asked once, with those records' addresses and entries:

    * a value whose records hold another row's code and none of this row's
      (the address right after a quoted value is its own place, not code);
    * an endpoint two rows naming different code both give, whose records
      hold the code of neither.

    A row that names no address, or a value no record of an entry holds, is
    not asked: nothing binds it either way.
    """
    channels = _rows(payload, "channels")
    if entries is None or len(channels) < 2:
        return []
    beside = _Beside(entries)
    code = [_channel_code(ch) for ch in channels]

    def own(index: int, value: str) -> set[int]:
        named, places, _quoted = code[index]
        skip = places.get(value.lower(), set())
        return {f for a in named if a not in skip for f in _forms(a, beside.bases)}

    def label(index: int) -> str:
        return f"channel {index + 1} ({str(channels[index].get('name') or '').strip()})"

    out: list[Violation] = []
    for index, channel in enumerate(channels):
        values = [
            *code[index][2],
            *(str(e) for e in channel.get("endpoints") or [] if str(e).strip()),
        ]
        for value in dict.fromkeys(values):
            forms, written, holders = beside.held(value)
            mine = own(index, value)
            if not forms or not mine or forms & mine:
                continue
            others = [d for d in range(len(channels)) if d != index and forms & own(d, value)]
            if not others:
                continue
            theirs = {f for d in others for f in own(d, value)}
            # The addresses the other rows name first: they are what binds the value.
            written = sorted(written, key=lambda a: not (_forms(int(a, 16), beside.bases) & theirs))
            out.append(
                Violation(
                    code=CHANNEL_BINDING_CODE,
                    message=(
                        f"{safe_finding_value(label(index))} gives "
                        f"{safe_finding_value(json.dumps(value))}, held in "
                        f"{safe_finding_value(', '.join(holders[:3]))} beside the code at "
                        f"{safe_finding_value(', '.join(written[:4]))}: the code "
                        f"{safe_finding_value(' and '.join(label(d) for d in others))} names, "
                        "not this row's. Give a value only to the channel whose code uses it, "
                        "and name that code."
                    ),
                    path=f"channels[{index}]",
                    values=(value,),
                )
            )
    # An endpoint two rows naming different code both give, bound to neither.
    rows_of: dict[str, list[int]] = {}
    for index, channel in enumerate(channels):
        for endpoint in channel.get("endpoints") or []:
            if str(endpoint).strip():
                rows_of.setdefault(str(endpoint).strip(), []).append(index)
    grouped: dict[tuple[int, ...], list[str]] = {}
    for endpoint, indexes in rows_of.items():
        rows = tuple(dict.fromkeys(indexes))
        if len(rows) < 2 or any(not own(i, endpoint) for i in rows):
            continue
        if len({frozenset(own(i, endpoint)) for i in rows}) < len(rows):
            continue
        forms, _written, _holders = beside.held(endpoint)
        if not forms or any(forms & own(i, endpoint) for i in rows):
            continue
        grouped.setdefault(rows, []).append(endpoint)
    for rows, endpoints in grouped.items():
        forms, written, holders = beside.held(endpoints[0])
        out.append(
            Violation(
                code=CHANNEL_BINDING_CODE,
                message=(
                    f"{safe_finding_value(' and '.join(label(i) for i in rows))} name "
                    "different code and both give "
                    f"{safe_finding_value(', '.join(json.dumps(e) for e in endpoints))}, held in "
                    f"{safe_finding_value(', '.join(holders[:3]))} beside the code at "
                    f"{safe_finding_value(', '.join(written[:4]))}, code neither row names. "
                    "Give an endpoint only to the channel whose code uses it; a channel whose "
                    "endpoints the "
                    "evidence does not name lists none."
                ),
                path="channels",
                values=tuple(endpoints),
            )
        )
    return out


# ---------------------------------------------------------------------------
# The values a composed section must carry
# ---------------------------------------------------------------------------

_CODE_SPAN = re.compile(r"`([^`\n]{2,120})`")
_ADDRESS_VALUE = re.compile(r"(?<![\w])0x[0-9a-fA-F]{2,16}(?![\w])")
_PATH_VALUE = re.compile(
    r"(?:[A-Za-z]:\\|%[A-Za-z_]+%\\|\\\\)[^\s\"'`,;()]+|(?<![\w.:/])/(?:[\w.-]+/)+[\w.-]*"
)
_REGISTRY_VALUE = re.compile(r"(?<![\w])HK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)\\[^\s\"'`,;()]+")
_FILE_NAME = re.compile(
    r"(?<![\w.-])[\w.-]+\.(?:exe|dll|sys|scr|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|lnk|msi"
    r"|com|cpl|ocx|py|sh|elf|so|dylib|jar|apk)(?![\w-])",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_ORDINAL_CALL = re.compile(r"[^\s\"'`]+,#\d+")
_QUOTED_VALUE = re.compile(
    r"[\"\u201c]([^\"\u201d\n]{2,80})[\"\u201d]|(?<![\w])'([^'\n]{2,80})'(?![\w])"
)
# An identifier with a digit or an underscore in it (a mutex, an export, a
# routine's name), or an API-style name of two or more humps (CreateMutexW);
# an evidence id is a citation, not a value.
_IDENTIFIER_VALUE = re.compile(
    r"(?<![\w])(?!ev_\d)(?=[A-Za-z0-9_]*[_\d])(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z_][A-Za-z0-9_]{3,}(?![\w])"
    r"|(?<![\w])[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*){2,}[A-Za-z0-9]*(?![\w])"
)
# A quoted ordinary word ('sample', "Marks") is no value.
_ORDINARY_WORD = re.compile(r"^[A-Za-z][a-z]+$")
# Algorithm, encoding and platform names that are no value of the sample's own.
_GENERIC_TOKENS = frozenset(
    {
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "md5",
        "crc32",
        "base64",
        "base32",
        "base85",
        "win32",
        "win64",
        "x86_64",
        "x86",
        "x64",
        "amd64",
        "arm64",
        "aes128",
        "aes192",
        "aes256",
        "rc4",
        "utf8",
        "utf_8",
        "utf16",
        "utf_16",
        "ipv4",
        "ipv6",
    }
)
_CITATIONS = re.compile(r"(?:\s*[\[(]\s*ev_\d+(?:\s*[,;]\s*ev_\d+)*\s*[\])])+")


@dataclass(frozen=True)
class ValueReader:
    """What counts as a value of the sample's own in a text, for one report.

    ``sample`` is the run's entry texts in :func:`carrying_form` (the tool
    outputs and the evidence tables the report holds); an identifier or a quoted
    string is a value only where it occurs there, and with no entry text at
    all every one is. ``family`` is the family the report attributes, a value
    wherever the text names it.
    """

    sample: str = ""
    family: str = ""

    @classmethod
    def of(cls, report: MalwareReport) -> ValueReader:
        return cls(sample=carrying_form(sample_text(report)), family=attributed_family(report))

    def __call__(self, text: str) -> list[str]:
        return carried_values(text, self)


def attributed_family(report: MalwareReport) -> str:
    """The family the report attributes, or ``""``."""
    family = str(getattr(report.attribution, "family", "") or "").strip()
    return family if family.lower() not in ("", "unknown", "none") else ""


def sample_text(report: MalwareReport) -> str:
    """The run's entry texts as the report holds them: every tool output and evidence table."""
    parts: list[str] = []
    for rows in (report.technical_evidence or {}).values():
        for row in rows or []:
            if isinstance(row, Mapping):
                parts.append(str(row.get("output") or ""))
    for section in report.sections:
        parts.extend(" ".join(str(cell) for cell in row) for row in section.rows)
    record = report.emulated_strings
    if record is not None:
        parts.extend([*record.values, *record.plain, *record.spelled.values()])
    return "\n".join(parts)


def carried_values(text: str, reader: ValueReader | None = None) -> list[str]:
    """The values ``text`` names, once each, in order: what a sentence that replaces it carries.

    Always a value: the hosts and addresses the unpublished-value check reads
    (``validation.network_values_in``), each email and its domain, code span,
    routine address, file path, registry key, file name with an executable or
    script extension, ordinal call (``x.dll,#1``), and the attributed family
    the text names. A value where the run's entries hold it (``reader``): a
    quoted string that is no ordinary word, and an identifier with a digit or
    an underscore or of two or more humps. Never: an ATT&CK id, or a generic
    algorithm, encoding or platform name (``SHA256``, ``Win32``).
    """
    from maljan.pipeline.validation import network_values_in

    reader = reader or ValueReader()
    plain = _CITATIONS.sub("", str(text or ""))
    found: list[str] = [value for _kind, value in network_values_in(plain)]
    for match in _EMAIL.finditer(plain):
        found.extend([match.group(0), match.group(1)])
    for pattern in (
        _CODE_SPAN,
        _ADDRESS_VALUE,
        _PATH_VALUE,
        _REGISTRY_VALUE,
        _FILE_NAME,
        _ORDINAL_CALL,
    ):
        for match in pattern.finditer(plain):
            value = (match.group(1) if match.groups() else match.group(0)).strip()
            # A sentence's own stop is no part of a path, key or file name.
            if pattern in (_PATH_VALUE, _REGISTRY_VALUE, _FILE_NAME):
                value = value.rstrip(".,:;")
            found.append(value)
    if reader.family and re.search(rf"(?i)(?<![\w]){re.escape(reader.family)}(?![\w])", plain):
        found.append(reader.family)
    sampled: list[str] = []
    for match in _QUOTED_VALUE.finditer(plain):
        quoted = (match.group(1) or match.group(2) or "").strip()
        # An ordinary word quoted is no value, unless the run's entries hold it
        # (a key or a password literal the sample carries).
        ordinary = bool(_ORDINARY_WORD.match(quoted)) and not (
            reader.sample and carrying_form(quoted) in reader.sample
        )
        if quoted and not ordinary:
            sampled.append(quoted)
    sampled.extend(m.group(0) for m in _IDENTIFIER_VALUE.finditer(plain))
    for value in sampled:
        if reader.sample and carrying_form(value) not in reader.sample:
            continue
        found.append(value)
    return [
        value
        for value in dict.fromkeys(found)
        if len(value) >= 2 and not _is_attack_id(value) and value.lower() not in _GENERIC_TOKENS
    ]


def _is_attack_id(value: str) -> bool:
    """Whether ``value`` is an ATT&CK technique or tactic id, in either case: no value."""
    upper = value.upper()
    return is_technique_id(upper) or TACTIC_ID_RE.match(upper) is not None


def carrying_form(text: str) -> str:
    """``text`` as values are looked for in it: refanged, unescaped, without marks, lower case."""
    plain = str(text or "")
    for written, value in (("[.]", "."), ("[@]", "@"), ("[:]", ":"), ("hxxp", "http")):
        plain = plain.replace(written, value)
    return re.sub(r"[`*\\]", "", plain).lower()


def values_not_carried(values: Sequence[str], text: str, *, formed: bool = False) -> list[str]:
    """The values of ``values`` that ``text`` does not hold, compared as :func:`carrying_form`.

    ``formed`` says ``text`` is in that form already, read once by its caller.
    """
    held = text if formed else carrying_form(text)
    return [value for value in values if carrying_form(value) not in held]


def evidence_text(bundle: Mapping[str, Any]) -> str:
    """The sample's own evidence a section is shown: its tool outputs and its functions' code.

    What the style check exempts a phrasing by (a sample's or a tool's term):
    never the headings, the instructions, the facts, the run state or a claim.
    """
    parts = [str(t.get("output") or "") for t in bundle.get("tool_outputs") or []]
    parts.extend(str(row.get("output") or "") for row in bundle.get("function_code") or [])
    return "\n".join(parts)


def summary_value_violations(
    payload: Any, findings: str, held: str, reader: ValueReader | None = None
) -> list[Violation]:
    """Values the key findings and the summary paragraph name that the bullets carry not, nor
    anything else the report held before the composer ran (``held``)."""
    bullets = " ".join(str(row.get("text") or "") for row in _rows(payload, "bullets"))
    if not bullets.strip():
        return []
    named = carried_values(findings, reader)
    dropped = values_not_carried(values_not_carried(named, bullets), held)
    if not dropped:
        return []
    return [
        Violation(
            code=VALUE_NOT_CARRIED_CODE,
            message=(
                "The key findings name "
                f"{safe_finding_value(', '.join(dropped[:8]))}, which no bullet carries and "
                "the report states nowhere else. Carry each in the bullet of its capability."
            ),
            path="bullets",
            values=tuple(dropped),
        )
    ]


def procedure_value_violations(
    payload: Any, firsts: Mapping[str, str], reader: ValueReader | None = None
) -> list[Violation]:
    """A procedure that drops a value its technique's first claim sentence names.

    ``firsts`` is each published technique's first claim sentence, the one the
    procedure replaces in the ATT&CK table.
    """
    out: list[Violation] = []
    for index, row in enumerate(_rows(payload, "procedures")):
        tid = str(row.get("technique_id") or "").strip().upper()
        first = firsts.get(tid, "")
        dropped = values_not_carried(carried_values(first, reader), str(row.get("procedure") or ""))
        if dropped:
            out.append(
                Violation(
                    code=VALUE_NOT_CARRIED_CODE,
                    message=(
                        f"The procedure for {safe_finding_value(tid)} drops "
                        f"{safe_finding_value(', '.join(dropped[:6]))}, which the first claim "
                        "names. Carry the value that shows the procedure."
                    ),
                    path=f"procedures[{index}].procedure",
                    values=tuple(dropped),
                )
            )
    return out


def first_claim_sentences(report: MalwareReport) -> dict[str, str]:
    """Each published technique's first claim sentence, as the ATT&CK table picks it."""
    out: dict[str, str] = {}
    for tid, (_name, claims, _refs) in published_techniques(report).items():
        if claims:
            text = _CITATIONS.sub("", claims[0])
            text = re.sub(r"^\s*\d{1,3}\.\s+", "", " ".join(text.split()))
            out[tid.upper()] = (sentences(text) or [""])[0]
    return out


def held_text(report: MalwareReport) -> str:
    """What the report holds before the composer runs, but for the prose the summary replaces."""
    # The composer's own fields are left out too, so a replay over a stored
    # report reads what the round read before any section was written.
    dumped = report.model_dump(
        mode="json",
        exclude={
            "key_findings",
            "executive_summary",
            "capabilities_narrative",
            "technical_analysis",
            "intro_background",
            "c2_channels",
        },
    )
    return json.dumps(dumped, ensure_ascii=False)
