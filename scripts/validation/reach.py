"""How far one tool server's evidence reached in a run: the six evidence-reach readings.

``reach(record, dump_dir, server_key)`` reads a rehearsal's ``RunRecord`` and
the request bodies its stub wrote (``Rehearsal.dump_dir``) and answers, for
the evidence entries of one source:

* **E1 recorded** — an ``evidence_index`` row of that source filed ``ok``;
* **E2 cited** — a claim in force cites one of its entry ids;
* **E3 validated** — no flagged statement against a claim citing it; where a
  declared entry appears in corroboration it is placed; whether an asserting
  source is among ``asserted_by``, and an undeclared entry read "unplaced",
  are recorded;
* **E4 composer** — its id or its answer reaches a composer section request;
* **E5 report** — a report section lists its id, Appendix A lists it, and
  the kind-specific places (code listing figure, "Functions examined",
  Reputation row, dynamic sections) are read off for the scenario to gate;
* **E6 nothing false** — no degradation names the source unavailable, no
  published text names a tool the scenario says the run did not use, and no
  entry filed ``ok`` reads as an error.

The source is matched by the entry's ``server`` or its ``source``
(``<server>``, ``mcp:<server>``, ``provider:<server>``), or by a predicate
the caller gives; nothing here names a tool.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from scripts.rehearsal import wire
from scripts.rehearsal.checklist import RunRecord
from scripts.rehearsal.inprocess import ANSWER_ROLES
from scripts.rehearsal.roles import composer_section

_EVIDENCE_ID = re.compile(r"\bev_\d{4,}\b")
# How a stored answer reads when its tool failed in words: checked on entries
# filed ``ok`` only, to be read by a person, never to excuse anything.
_ERROR_WORDS = re.compile(
    r"^\s*(?:\{\s*\"error\"|error\b|exception\b|traceback\b|failed\b|not found\b|"
    r"no such\b|invalid\b|unknown tool\b)",
    re.IGNORECASE,
)
# The words of a flagged statement's code that say it is about grounding or citation.
_GROUNDING_CODE = re.compile(r"ground|cit", re.IGNORECASE)
# The shortest answer head that counts as the answer reaching a section.
_ANSWER_HEAD = 24

Entry = dict[str, Any]
Match = Callable[[Entry], bool]


def by_server(server_key: str) -> Match:
    """Entries of ``server_key``, by their server or their recorded source."""
    sources = {server_key, f"mcp:{server_key}", f"provider:{server_key}"}

    def match(entry: Entry) -> bool:
        return entry.get("server") == server_key or str(entry.get("source") or "") in sources

    return match


def entries_of(record: RunRecord, match: Match) -> list[Entry]:
    """The evidence index rows ``match`` takes, in order."""
    index = record.malware_report.get("evidence_index") or []
    return [row for row in index if isinstance(row, dict) and match(row)]


def answers_of(record: RunRecord) -> dict[str, str]:
    """Each entry id's stored answer, from the report's technical evidence."""
    out: dict[str, str] = {}
    for outputs in (record.malware_report.get("technical_evidence") or {}).values():
        for item in outputs or []:
            seq = item.get("seq") if isinstance(item, dict) else None
            if isinstance(seq, int):
                out.setdefault(f"ev_{seq + 1:04d}", str(item.get("output") or ""))
    for event in record.events:
        if event.get("type") == "tool_call_finished" and event.get("evidence_id"):
            out.setdefault(str(event["evidence_id"]), str(event.get("summary") or ""))
    return out


def claims_citing(record: RunRecord, ids: Iterable[str]) -> list[dict[str, Any]]:
    """The claims in force whose evidence reference names one of ``ids``.

    The answer in force is each analyst's last message with claims, a debate's
    revision included (``inprocess.claims_from_events``).
    """
    wanted = set(ids)
    in_force: dict[str, list[dict[str, Any]]] = {}
    for event in record.events:
        if event.get("type") != "agent_message" or event.get("role") not in ANSWER_ROLES:
            continue
        claims = event.get("claims")
        speaker = str(event.get("speaker") or "")
        if isinstance(claims, list) and claims and speaker:
            in_force[speaker] = [c for c in claims if isinstance(c, dict)]
    out: list[dict[str, Any]] = []
    for speaker, claims in in_force.items():
        for claim in claims:
            cited = set(_EVIDENCE_ID.findall(str(claim.get("evidence_ref") or "")))
            if cited & wanted:
                out.append({"agent": speaker, **claim, "cites": sorted(cited & wanted)})
    return out


def composer_requests(dump_dir: Path | None) -> dict[str, str]:
    """Each composer section's request text, from the bodies the stub wrote (H4).

    A section asked twice keeps both texts joined; the probe's own requests
    are never composer requests.
    """
    out: dict[str, str] = {}
    if dump_dir is None or not Path(dump_dir).is_dir():
        return out
    for path in sorted(Path(dump_dir).glob("*-composer.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        request = wire.read_anthropic(body) if "system" in body else wire.read_openai(body)
        section = composer_section(request) or path.stem
        out[section] = "\n".join(filter(None, (out.get(section, ""), request.all_text)))
    return out


def requests_of_role(dump_dir: Path | None, role: str) -> list[str]:
    """The request texts the stub answered as ``role``, in order."""
    texts: list[str] = []
    if dump_dir is None or not Path(dump_dir).is_dir():
        return texts
    for path in sorted(Path(dump_dir).glob(f"*-{role}.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        request = wire.read_anthropic(body) if "system" in body else wire.read_openai(body)
        texts.append(request.all_text)
    return texts


def tools_offered(dump_dir: Path | None, role: str = "analyst") -> list[str]:
    """Every tool name offered to the stub in the requests it answered as ``role``."""
    names: set[str] = set()
    if dump_dir is None or not Path(dump_dir).is_dir():
        return []
    for path in sorted(Path(dump_dir).glob(f"*-{role}.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        request = wire.read_anthropic(body) if "system" in body else wire.read_openai(body)
        names.update(request.tool_names)
    return sorted(names)


def _appendix_ids(markdown: str) -> set[str]:
    start = markdown.find("Appendix A")
    if start < 0:
        return set()
    return set(re.findall(r"^\|\s*(ev_\d{4,})\s*\|", markdown[start:], re.MULTILINE))


def _placement(record: RunRecord, ids: set[str]) -> tuple[list[str], list[str], list[str]]:
    """The ids corroboration placed, read unplaced, and lists among its sources."""
    placed: set[str] = set()
    unplaced: set[str] = set()
    listed: set[str] = set()
    for row in (record.run_summary.get("corroboration") or {}).values():
        if not isinstance(row, dict):
            continue
        sources = {str(s) for s in row.get("sources") or []} & ids
        not_read = {
            str(line).split(":", 1)[0] for line in row.get("roots_not_read") or [] if line
        } & ids
        listed |= sources
        unplaced |= not_read
        placed |= sources - not_read
    return sorted(placed), sorted(unplaced - placed), sorted(listed)


def _asserted(record: RunRecord, entries: list[Entry]) -> dict[str, bool]:
    """Each asserting entry's source, and whether corroboration counts it among ``asserted_by``."""
    sayers = {
        str(s)
        for row in (record.run_summary.get("corroboration") or {}).values()
        if isinstance(row, dict)
        for s in row.get("asserted_by") or []
    }
    out: dict[str, bool] = {}
    for entry in entries:
        facts = entry.get("facts") or {}
        if facts.get("asserts_techniques"):
            source = str(facts.get("source") or entry.get("server") or "")
            out[source] = source in sayers
    return out


def _published(record: RunRecord) -> dict[str, str]:
    return {
        "markdown": record.markdown,
        "stix": json.dumps(record.stix_bundle or {}, ensure_ascii=False, default=str),
        "stix_extended": json.dumps(record.stix_extended or {}, ensure_ascii=False, default=str),
        "degradations": json.dumps(
            record.malware_report.get("degradation_reasons") or [], ensure_ascii=False
        ),
    }


def absent_names(record: RunRecord, names: Iterable[str]) -> dict[str, list[str]]:
    """Each of ``names`` the run's published text or degradations still mention, and where."""
    published = _published(record)
    found: dict[str, list[str]] = {}
    for name in names:
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        where = [place for place, text in published.items() if pattern.search(text)]
        if where:
            found[name] = where
    return found


def reach(
    record: RunRecord,
    dump_dir: Path | None,
    server_key: str,
    *,
    match: Match | None = None,
    absent: Iterable[str] = (),
) -> dict[str, Any]:
    """The E1–E6 readings for ``server_key``'s entries (or ``match``'s) in this run."""
    entries = entries_of(record, match or by_server(server_key))
    ids = [str(e.get("id")) for e in entries]
    ok_ids = [str(e.get("id")) for e in entries if e.get("ok")]
    answers = answers_of(record)
    mr = record.malware_report

    e1 = {"ok": bool(ok_ids), "entries": ids, "ok_entries": ok_ids}

    citing = claims_citing(record, ok_ids)
    cited = sorted({i for c in citing for i in c["cites"]})
    e2 = {"ok": bool(cited), "cited": cited, "claims": [c.get("claim", "") for c in citing]}

    flagged = [
        row
        for row in mr.get("flagged_statements") or []
        if isinstance(row, dict)
        and _GROUNDING_CODE.search(str(row.get("code") or ""))
        and any(
            str(c.get("claim") or "")[:60]
            and str(c.get("claim") or "")[:60] in str(row.get("sentence"))
            for c in citing
        )
    ]
    placed, unplaced, listed = _placement(record, set(ok_ids))
    declared = {str(e.get("id")) for e in entries if (e.get("facts") or {}).get("kind")}
    declared_listed = sorted(set(listed) & declared)
    asserted = _asserted(record, entries)
    e3_ok = not flagged and (not declared_listed or bool(set(placed) & declared))
    e3 = {
        "ok": e3_ok,
        "flagged": flagged,
        "placed": placed,
        "unplaced": unplaced,
        "declared": sorted(declared),
        "undeclared": sorted(set(ok_ids) - declared),
        "asserted": asserted,
    }

    sections_seen: dict[str, list[str]] = {}
    for section, text in composer_requests(dump_dir).items():
        hits = []
        for entry_id in ok_ids:
            head = answers.get(entry_id, "").strip()[:80]
            if entry_id in text or (len(head) >= _ANSWER_HEAD and head in text):
                hits.append(entry_id)
        if hits:
            sections_seen[section] = hits
    e4 = {"ok": bool(sections_seen), "sections": sections_seen}

    report_sections = [
        str(s.get("key"))
        for s in mr.get("sections") or []
        if isinstance(s, dict) and set(s.get("evidence_ids") or []) & set(ok_ids)
    ]
    appendix = sorted(_appendix_ids(record.markdown) & set(ids))
    listings = [
        f
        for f in mr.get("figures") or []
        if isinstance(f, dict) and f.get("kind") == "code_listing"
    ]
    own_heads = [answers.get(i, "").strip()[:40] for i in ok_ids if answers.get(i, "").strip()]
    listing_from_source = any(
        head and head.split("\n", 1)[0] in str(f.get("content") or "")
        for f in listings
        for head in own_heads
    )
    functions_examined = any(
        isinstance(s, dict)
        and s.get("key") == "functions_examined"
        and set(s.get("evidence_ids") or []) & set(ok_ids)
        for s in mr.get("sections") or []
    )
    reputation_rows = [
        r
        for r in mr.get("reputation") or []
        if isinstance(r, dict) and str(r.get("entry_id") or "") in set(ok_ids)
    ]
    e5 = {
        "ok": bool(report_sections) and bool(appendix),
        "sections": report_sections,
        "appendix": appendix,
        "code_listing_figures": len(listings),
        "listing_from_source": listing_from_source,
        "functions_examined": functions_examined,
        "reputation_rows": reputation_rows,
    }

    degradations = [str(d) for d in mr.get("degradation_reasons") or []]
    naming = [
        d for d in degradations if server_key and server_key in d and "unavailable" in d.lower()
    ]
    named_absent = absent_names(record, absent)
    suspect = [i for i in ok_ids if _ERROR_WORDS.match(answers.get(i, ""))]
    e6 = {
        "ok": not naming and not named_absent and not suspect,
        "degradations_naming": naming,
        "absent_named": named_absent,
        "ok_but_reads_as_error": suspect,
    }
    return {"server": server_key, "E1": e1, "E2": e2, "E3": e3, "E4": e4, "E5": e5, "E6": e6}


def reach_markdown(rows: list[dict[str, Any]]) -> str:
    """A table of reach readings, one row per source."""
    lines = ["| Source | E1 | E2 | E3 | E4 | E5 | E6 |", "|---|---|---|---|---|---|---|"]
    for row in rows:
        marks = ["yes" if row[e]["ok"] else "NO" for e in ("E1", "E2", "E3", "E4", "E5", "E6")]
        lines.append(f"| {row['server']} | " + " | ".join(marks) + " |")
    return "\n".join(lines)
