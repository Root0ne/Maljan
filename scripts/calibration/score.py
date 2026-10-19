"""Score a stored run of a calibration case against the case's manifest, deterministically.

The run is read, never written, by the replay's reader
(``scripts.replay.stored.read_run``; every file is digested before and after),
and everything is read as the run stored it: no publish rule, table or answer
is computed again with today's code.

What is read:

- **tool and pack rows**: ``static`` and ``emulated_strings`` of
  ``report.json`` and the cells of every report section a tool's answer or the
  routing wrote (section source in :data:`TOOL_SOURCES`). An analyst's
  ``artifact:`` table and a findings table are model text, not tool rows;
- **kept claims**: the claims in force (``agent_findings`` of the report row)
  that cite a ledger entry the run holds;
- **publications as stored**: the ATT&CK table's technique ids
  (``ttp_mappings``), the capability matrix cells stored with an empty
  ``not_published``, and the stored IOC rows (``consolidated_iocs``) whose stored
  publish answer is yes, the sample's own identity rows aside. A part the run
  did not store is **not recorded**, never computed;
- **what the platform held back**: matrix cells stored with a ``not_published``
  reason, stored IOC rows answered no, and positive claims in force whose
  technique is not published (a claim that reads as absence is no claim of the
  item: its stored ``kept_after_absence_question`` flag, or the platform's own
  absence reading, ``validation.states_absence``);
- **free text**: every other string of ``report.json`` and the report row;
- **the evidence exports**: each ledger entry's ``output`` and ``structured``.

A fact is **found** when a tool or pack row holds every term (read as
:data:`FACT_READING` says for its kind), when one kept claim states every term
and the ledger entries it cites hold every term (after the same folding), or
when the report publishes the fact's own indicator; **partial** when the rows
hold some terms, when only its technique is published (that is not evidence
of the specific fact), or when only the evidence holds every term;
**mentioned** when only free text names it; and **missed** otherwise.

A trap or an absent capability is **false** only when the stored publications
claim it (a technique or one beneath it, a published capability cell, a
published indicator that names it); **not recorded** when the part it would be
published in was not stored; **withheld** when the platform held a positive
claim of it back; **mentioned** when only free text names it, a denial
included; otherwise **clear**. The ``false`` total counts each published
technique or indicator once, however many items it claims. A published
technique or indicator no fact, trap or absence speaks of is listed as
**beyond** the manifest. Nothing here asks a model.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.calibration.cases import covers
from scripts.replay.stored import check_unchanged, digests, read_run

from maljan.pipeline.claim_drops import _refanged

# Fields of report.json that index what the run's tools saw or how the run
# went: neither a tool row nor free text.
REPORT_BOOKKEEPING: dict[str, str] = {
    "evidence_index": "the ledger's entries, by id and tool",
    "tool_queries": "the values a tool was asked about",
    "tool_sightings": "the values a tool's answer held",
    "run_summary": "counts, timings and the settings snapshot",
    "front_matter": "the title page",
    "version_history": "the report's own versions",
}
# Fields of report.json a tool fills: tool rows.
TOOL_FIELDS: dict[str, str] = {
    "static": "the PE header, sections, imports, exports, packer and strings tables",
    "emulated_strings": "the strings an emulator or decoder recovered",
}
# Fields read as publications, not as text.
PUBLICATION_FIELDS: tuple[str, ...] = ("ttp_mappings", "capability_matrix", "consolidated_iocs")
# A report section a tool's answer or the routing wrote, by the head of its
# source. ``artifact:`` (an analyst's table) and ``finding`` are model text.
TOOL_SOURCES: tuple[str, ...] = ("tool", "routing")
# A row of the IOC table that is the sample's own digest.
IDENTITY_SOURCE = "identity"
# A ledger entry id, as a claim cites it.
_ENTRY_ID = re.compile(r"\bev_\d+\b")

TOKEN, DECODED, SECTION = "token", "decoded", "section"
# How each manifest fact kind is read from the tool and pack rows.
FACT_READING: dict[str, tuple[str, str]] = {
    "import": (TOKEN, "a whole token of a tool row: static.imports, an import-table cell"),
    "export": (TOKEN, "a whole token of a tool row: static.exports, an export-table cell"),
    "string": (TOKEN, "a whole token of a tool row: the strings table"),
    "api_hash": (TOKEN, "a whole token of a tool row: a hash resolver's answer"),
    "packed": (TOKEN, "a whole token of a tool row: static.packer_*, a packer tool's answer"),
    "xor_string": (DECODED, "inside a tool row: emulated_strings, a decoder's answer"),
    "config": (DECODED, "inside a tool row: a decoder's text and key"),
    "section_anomaly": (
        SECTION,
        "static.sections: the section flagged (is_suspicious, or WRITE and EXECUTE); "
        "listed but not flagged is partial",
    ),
}
_TOKEN = re.compile(r"[a-z0-9_.\-]+")

FOUND, PARTIAL, MENTIONED, MISSED = "found", "partial", "mentioned", "missed"
FALSE, WITHHELD, CLEAR, NOT_RECORDED = "false", "withheld", "clear", "not recorded"
FACT_STATUSES = (FOUND, PARTIAL, MENTIONED, MISSED)
TOTAL_KEYS = (FOUND, PARTIAL, MENTIONED, MISSED, FALSE, WITHHELD, NOT_RECORDED, "beyond")


class ScoreError(RuntimeError):
    """A run cannot be scored; the message names why."""


@dataclass
class Surfaces:
    """What a stored run is scored on."""

    name: str
    sample_sha256: str
    tool_text: str
    tool_tokens: set[str]
    flagged_sections: set[str]
    # Each kept claim's text and the text of the ledger entries it cites.
    kept_claims: list[tuple[str, str]]
    free_text: str
    free_tokens: set[str]
    evidence_text: str
    # None: the run did not store that part.
    techniques: list[str] | None
    indicators: list[tuple[str, str]] | None
    withheld_techniques: list[str] = field(default_factory=list)
    withheld_indicators: list[str] = field(default_factory=list)
    # What the run lacks that the score would have read, by part.
    not_read: dict[str, str] = field(default_factory=dict)


def _fold(text: str) -> str:
    return _refanged(text).casefold()


def _strings(value: Any, keys: bool = False) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if keys:
                yield str(key)
            yield from _strings(item, keys)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item, keys)


def _sample_sha256(run: Any) -> str:
    job = run.job or {}
    if isinstance(job.get("sample_sha256"), str) and job["sample_sha256"]:
        return str(job["sample_sha256"]).lower()
    identity = (run.report or {}).get("identity")
    hashes = identity.get("hashes") if isinstance(identity, dict) else None
    sha = hashes.get("sha256") if isinstance(hashes, dict) else None
    return str(sha).lower() if isinstance(sha, str) else ""


def _is_tool_section(section: Any) -> bool:
    source = str(section.get("source") or "") if isinstance(section, dict) else ""
    return source.split(":", 1)[0] in TOOL_SOURCES


def _flagged(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    flags = set(str(row.get("characteristics") or "").upper().split("|"))
    return bool(row.get("is_suspicious")) or {"WRITE", "EXECUTE"} <= flags


def _reads_as_absence(claim: dict[str, Any], technique: str) -> bool:
    from maljan.pipeline.validation import behaviour_pattern, states_absence

    if claim.get("kept_after_absence_question"):
        return True
    return states_absence(str(claim.get("claim") or ""), behaviour_pattern(technique))


def _stored_publications(
    document: dict[str, Any], claims: list[dict[str, Any]], not_read: dict[str, str]
) -> tuple[list[str] | None, list[tuple[str, str]] | None, list[str], list[str]]:
    """Published techniques and indicators, and those held back, as the run stored them."""
    from maljan.reporting.renderers.stix_renderer import publishes

    mappings = document.get("ttp_mappings")
    techniques: list[str] | None = None
    if isinstance(mappings, list):
        techniques = [
            str(m.get("technique_id")).strip().upper()
            for m in mappings
            if isinstance(m, dict) and str(m.get("technique_id") or "").strip()
        ]
    else:
        not_read["techniques"] = "report.json stores no ttp_mappings: techniques not recorded"
    withheld_techniques: list[str] = []
    for cell in document.get("capability_matrix") or []:
        technique = str((cell or {}).get("technique_id") or "").strip().upper()
        if not technique or "not_published" not in cell:
            continue
        if cell["not_published"]:
            withheld_techniques.append(technique)
        elif techniques is not None and technique not in techniques:
            techniques.append(technique)
    for claim in claims:
        technique = str(claim.get("technique_id") or "").strip().upper()
        if (
            technique
            and techniques is not None
            and not any(covers(t, technique) for t in techniques)
            and not _reads_as_absence(claim, technique)
        ):
            withheld_techniques.append(technique)

    rows = [
        r
        for r in document.get("consolidated_iocs") or []
        if isinstance(r, dict) and r.get("source") != IDENTITY_SOURCE
    ]
    indicators: list[tuple[str, str]] | None = None
    withheld_indicators: list[str] = []
    if any("published" in r and r["published"] is not None for r in rows):
        indicators = [
            (str(r.get("kind") or r.get("type")), str(r.get("value")))
            for r in rows
            if publishes(r.get("published"))
        ]
        withheld_indicators = [
            str(r.get("value")) for r in rows if not publishes(r.get("published"))
        ]
    else:
        not_read["indicators"] = (
            "report.json stores no IOC row with a publish answer: indicators not recorded"
        )
    return techniques, indicators, sorted(set(withheld_techniques)), withheld_indicators


def read_surfaces(root: Path) -> Surfaces:
    """The scored parts of the stored run in ``root``, read without writing to it."""
    root = Path(root)
    before = digests(root)
    run = read_run(root)
    if run.report is None:
        reason = run.unreadable.get("report.json", "absent")
        raise ScoreError(f"{root}: no report to score (report.json: {reason})")
    not_read: dict[str, str] = {}
    if "evidence.json" in run.unreadable:
        not_read["evidence"] = f"evidence.json did not parse ({run.unreadable['evidence.json']})"
    elif "evidence.json" not in run.present:
        not_read["evidence"] = "evidence.json is absent: no claim's citation could be checked"
    if "report-byjob.json" not in run.present:
        not_read["claims"] = "report-byjob.json is absent: no claims in force were read"

    document: dict[str, Any] = run.report
    found_sections = document.get("sections")
    sections: list[Any] = found_sections if isinstance(found_sections, list) else []
    tool_parts = [
        *(s for k in TOOL_FIELDS for s in _strings(document.get(k), keys=True)),
        *(
            s
            for t in sections
            if _is_tool_section(t)
            for s in _strings([t.get("rows"), t.get("items"), t.get("text")])
        ),
    ]
    claims = [
        claim
        for finding in run.agent_findings
        for claim in finding.get("claims") or []
        if isinstance(claim, dict)
    ]
    entry_texts = {
        str(item.get("entry_id")): _fold(
            "\n".join([str(item.get("output") or ""), *_strings(item.get("structured"))])
        )
        for item in run.evidence
    }
    kept: list[tuple[str, str]] = []
    for claim in claims:
        cited = [
            entry_texts[i]
            for i in _ENTRY_ID.findall(str(claim.get("evidence_ref") or ""))
            if i in entry_texts
        ]
        if cited:
            kept.append((_fold(str(claim.get("claim") or "")), "\n".join(cited)))
    free = {
        k: v
        for k, v in document.items()
        if k not in REPORT_BOOKKEEPING
        and k not in TOOL_FIELDS
        and k not in PUBLICATION_FIELDS
        and k != "sections"
    }
    free_parts = [
        *_strings(free),
        *(s for section in sections if not _is_tool_section(section) for s in _strings(section)),
        *_strings(claims),
        *run.agent_reports.values(),
    ]
    found_static = document.get("static")
    static: dict[str, Any] = found_static if isinstance(found_static, dict) else {}
    flagged = {
        str(row.get("name") or "").casefold()
        for row in static.get("sections") or []
        if _flagged(row)
    }
    evidence_parts: list[str] = []
    for item in run.evidence:
        evidence_parts.append(str(item.get("output") or ""))
        evidence_parts.extend(_strings(item.get("structured")))
    techniques, indicators, withheld_t, withheld_i = _stored_publications(
        document, claims, not_read
    )
    tool_text = _fold("\n".join(tool_parts))
    free_text = _fold("\n".join(free_parts))
    surfaces = Surfaces(
        name=run.name,
        sample_sha256=_sample_sha256(run),
        tool_text=tool_text,
        tool_tokens=set(_TOKEN.findall(tool_text)),
        flagged_sections=flagged,
        kept_claims=kept,
        free_text=free_text,
        free_tokens=set(_TOKEN.findall(free_text)),
        evidence_text=_fold("\n".join(evidence_parts)),
        techniques=techniques,
        indicators=indicators,
        withheld_techniques=withheld_t,
        withheld_indicators=withheld_i,
        not_read=not_read,
    )
    check_unchanged(before, digests(root))
    return surfaces


def _held(term: Iterable[str], mode: str, surfaces: Surfaces) -> bool:
    if mode == DECODED:
        return any(_fold(s) in surfaces.tool_text for s in term)
    return any(_fold(s) in surfaces.tool_tokens for s in term)


def _in(term: Iterable[str], text: str) -> bool:
    return any(_fold(spelling) in text for spelling in term)


def _names(indicator: str, value: str) -> bool:
    return _fold(indicator).rstrip(".") in _fold(value).rstrip(".")


def _indicator_published(fact: dict[str, Any], surfaces: Surfaces) -> bool:
    """A published indicator that is the fact's own value: evidence of the fact itself."""
    return any(
        _names(k, v) for _, v in surfaces.indicators or [] for k in fact.get("indicators", [])
    )


def _technique_published(fact: dict[str, Any], surfaces: Surfaces) -> bool:
    """A published technique the fact is evidence of: not evidence of the fact itself."""
    return any(covers(t, k) for t in surfaces.techniques or [] for k in fact.get("techniques", []))


def _claimed(terms: list[list[str]], surfaces: Surfaces) -> bool:
    """A kept claim states every term, and the entries it cites hold every term too."""
    return bool(terms) and any(
        all(_in(t, claim) and _in(t, cited) for t in terms) for claim, cited in surfaces.kept_claims
    )


def _fact(fact: dict[str, Any], surfaces: Surfaces) -> dict[str, Any]:
    kind = fact["kind"]
    if kind not in FACT_READING:
        raise ScoreError(f"fact {fact['id']}: no reading for the kind {kind!r}")
    mode = FACT_READING[kind][0]
    terms = fact.get("terms") or []
    held = sum(1 for term in terms if _held(term, mode, surfaces))
    flagged = any(_fold(s) in surfaces.flagged_sections for term in terms for s in term)
    if mode == SECTION and held and not flagged:
        status, why = PARTIAL, "the section is listed and not flagged"
    elif terms and held == len(terms):
        status, why = FOUND, "a tool or pack row holds every term"
    elif _claimed(terms, surfaces):
        status, why = FOUND, "a kept claim states every term, and the entries it cites hold them"
    elif _indicator_published(fact, surfaces):
        status, why = FOUND, "the report publishes the fact's own indicator"
    elif held:
        status, why = PARTIAL, f"the tool rows hold {held} of {len(terms)} terms"
    elif _technique_published(fact, surfaces):
        status, why = PARTIAL, "the report publishes its technique; nothing names the fact itself"
    elif terms and all(_in(term, surfaces.evidence_text) for term in terms):
        status, why = PARTIAL, "only the evidence holds it"
    elif any(_in(term, surfaces.free_text) for term in terms):
        status, why = MENTIONED, "only free text names it"
    else:
        status, why = MISSED, ""
    return {
        "id": fact["id"],
        "kind": kind,
        "difficulty": fact["difficulty"],
        "status": status,
        "why": why,
    }


def _claims(item: dict[str, Any], surfaces: Surfaces) -> dict[str, Any]:
    claims = item.get("claims") or {}
    techniques = claims.get("techniques", [])
    indicators = claims.get("indicators", [])
    published = sorted(
        {t for t in surfaces.techniques or [] for c in techniques if covers(t, c)}
        | {v for _, v in surfaces.indicators or [] for c in indicators if _names(c, v)}
    )
    unrecorded = (techniques and surfaces.techniques is None) or (
        indicators and surfaces.indicators is None
    )
    withheld = sorted(
        {t for t in surfaces.withheld_techniques for c in techniques if covers(t, c)}
        | {v for v in surfaces.withheld_indicators for c in indicators if _names(c, v)}
    )
    named = [item.get("subject") or "", *indicators]
    mentioned = any(n and _fold(n) in surfaces.free_text for n in named) or any(
        covers(token.upper(), t) for t in techniques for token in surfaces.free_tokens
    )
    if published:
        status = FALSE
    elif unrecorded:
        status = NOT_RECORDED
    elif withheld:
        status = WITHHELD
    elif mentioned:
        status = MENTIONED
    else:
        status = CLEAR
    return {
        "id": item["id"],
        "kind": item.get("kind") or "absent",
        "status": status,
        "published": published,
        "withheld": withheld,
    }


def score(manifest: dict[str, Any], surfaces: Surfaces) -> dict[str, Any]:
    """The score of one run against one manifest."""
    facts = [_fact(f, surfaces) for f in manifest.get("facts", [])]
    traps = [_claims(t, surfaces) for t in manifest.get("traps", [])]
    absent = [_claims(a, surfaces) for a in manifest.get("absent", [])]

    known_techniques = [t for f in manifest.get("facts", []) for t in f.get("techniques", [])]
    known_indicators = [i for f in manifest.get("facts", []) for i in f.get("indicators", [])]
    for item in [*manifest.get("traps", []), *manifest.get("absent", [])]:
        known_techniques += (item.get("claims") or {}).get("techniques", [])
        known_indicators += (item.get("claims") or {}).get("indicators", [])
    beyond_techniques = [
        t for t in surfaces.techniques or [] if not any(covers(t, k) for k in known_techniques)
    ]
    beyond_indicators = [
        [kind, value]
        for kind, value in surfaces.indicators or []
        if not any(_names(k, value) for k in known_indicators)
    ]

    def count(rows: list[dict[str, Any]], status: str, difficulty: str | None = None) -> int:
        return sum(
            1
            for r in rows
            if r["status"] == status and (difficulty is None or r["difficulty"] == difficulty)
        )

    difficulties = sorted({f["difficulty"] for f in facts})
    totals: dict[str, Any] = {s: count(facts, s) for s in FACT_STATUSES}
    # Each published technique or indicator once, however many items it claims.
    totals[FALSE] = len({v for item in [*traps, *absent] for v in item["published"]})
    totals[WITHHELD] = count(traps, WITHHELD) + count(absent, WITHHELD)
    totals[NOT_RECORDED] = count(traps, NOT_RECORDED) + count(absent, NOT_RECORDED)
    totals["beyond"] = len(beyond_techniques) + len(beyond_indicators)
    totals["by_difficulty"] = {
        d: {s: count(facts, s, d) for s in FACT_STATUSES} for d in difficulties
    }
    return {
        "case": manifest["case"],
        "split": manifest["split"],
        "run": surfaces.name,
        "facts": facts,
        "traps": traps,
        "absent": absent,
        "beyond": {"techniques": beyond_techniques, "indicators": beyond_indicators},
        "not_read": dict(surfaces.not_read),
        "totals": totals,
    }


def summed(scores: list[dict[str, Any]]) -> dict[str, int]:
    """The totals of several scores added up."""
    return {k: sum(int(s["totals"][k]) for s in scores) for k in TOTAL_KEYS}


def redacted(result: dict[str, Any]) -> dict[str, Any]:
    """A score with ids, kinds and verdicts only: no reason, claimed value or beyond value."""
    keep = ("id", "kind", "difficulty", "status")
    return {
        **result,
        "facts": [{k: f[k] for k in keep} for f in result["facts"]],
        "traps": [{k: t[k] for k in keep if k in t} for t in result["traps"]],
        "absent": [{k: a[k] for k in keep if k in a} for a in result["absent"]],
        "beyond": {
            "techniques": len(result["beyond"]["techniques"]),
            "indicators": len(result["beyond"]["indicators"]),
        },
    }


def render(result: dict[str, Any], *, show_answers: bool) -> str:
    """One score as text; without ``show_answers`` it names ids, kinds and verdicts only."""
    totals = result["totals"]
    lines = [
        f"{result['run']}: case {result['case']} ({result['split']})",
        "  " + "  ".join(f"{k} {totals[k]}" for k in TOTAL_KEYS),
    ]
    for difficulty, row in totals["by_difficulty"].items():
        lines.append(f"  {difficulty}: " + "  ".join(f"{s} {row[s]}" for s in FACT_STATUSES))
    for part, why in result["not_read"].items():
        lines.append(f"  not read: {part}: {why}")
    for fact in result["facts"]:
        why = f" ({fact['why']})" if show_answers and fact.get("why") else ""
        lines.append(f"  {fact['id']} {fact['kind']} [{fact['difficulty']}]: {fact['status']}{why}")
    for item in [*result["traps"], *result["absent"]]:
        what = ""
        if show_answers and item["status"] in (FALSE, WITHHELD):
            what = " (" + ", ".join(item["published"] or item["withheld"]) + ")"
        lines.append(f"  {item['id']} {item['kind']}: {item['status']}{what}")
    if show_answers:
        for technique in result["beyond"]["techniques"]:
            lines.append(f"  beyond: technique {technique}")
        for kind, value in result["beyond"]["indicators"]:
            lines.append(f"  beyond: {kind} {value}")
    return "\n".join(lines)


def write_json(path: Path, payload: Any) -> None:
    Path(path).write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
