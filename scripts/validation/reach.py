"""How far one tool server's evidence reached in a run: the six evidence-reach readings.

``reach(record, dump_dir, server_key)`` reads a rehearsal's ``RunRecord`` and
the request bodies its stub wrote (``Rehearsal.dump_dir``) and answers, for
the evidence entries of one source:

* **E1 recorded** — an ``evidence_index`` row of that source filed ``ok``;
* **E2 cited** — a claim in force cites one of its entry ids;
* **E3 validated** — a claim cites it where the scenario expects one; no
  flagged statement against a claim citing it; a declared entry reaches
  corroboration and is placed there; an asserting declared source is among
  ``asserted_by``; an undeclared entry read "unplaced" is recorded, never
  failed;
* **E4 composer** — its id or its answer reaches a composer section request;
* **E5 report** — a report section lists its id, Appendix A lists it, and
  the kind-specific places (code listing figure, "Functions examined",
  Reputation row, dynamic sections) are read off for the scenario to gate;
  code evidence is credited only for a decompile or disassembly answer that
  holds code, at a place an answer of the same source listed as a function
  start (``code_evidence``);
* **E6 nothing false** — no degradation names the source unavailable, no
  published text names a tool the scenario says the run did not use, and no
  entry filed ``ok`` reads as an error, and no figure draws an answer filed
  as failed.

The source is matched by the entry's ``server`` or its ``source``
(``<server>``, ``mcp:<server>``, ``provider:<server>``), or by a predicate
the caller gives; nothing here names a tool. Each reading that misses says
why in ``why``, in words that name no entry id, so a pinned product gap
matches exactly from one run to the next.
"""

from __future__ import annotations

import html
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
# The declared kinds whose answers are code read at a place.
CODE_KINDS = ("decompile", "disassembly", "function_disassembly")
# A place as an answer or an argument spells it: a hex address, or a name a
# disassembler gives a function it found no name for (its hex part read).
_PLACE = re.compile(r"\b0x([0-9A-Fa-f]{1,16})\b|\b(?:FUN_|fcn\.|sub_)([0-9A-Fa-f]{4,16})\b")
# A tool name or declared kind naming the program's functions or entry points:
# a whole word of it (``function_list``, ``entrypoints``; never ``entropy``).
_LISTS_FUNCTIONS = re.compile(r"(?:^|_)(?:functions?|entry_?points?)(?:_|$)", re.IGNORECASE)
# An ATT&CK technique id as an answer names one.
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# A listing line's leading address, taken off before its text is read.
_LINE_ADDRESS = re.compile(r"^\s*(?:0x)?[0-9A-Fa-f]{4,16}:?\s+")

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


def calls_by_entry(dump_dir: Path | None) -> dict[str, dict[str, Any]]:
    """Each entry id's call as the model made it: ``{"tool", "args"}``, from the dumped bodies.

    A tool answer the product hands back starts with the id it filed the call
    under; the call that answer belongs to carries the arguments.
    """
    out: dict[str, dict[str, Any]] = {}
    if dump_dir is None or not Path(dump_dir).is_dir():
        return out
    for path in sorted(Path(dump_dir).glob("*.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(body, dict):
            continue
        request = wire.read_anthropic(body) if "system" in body else wire.read_openai(body)
        calls = {c.id: c for c in request.tool_calls_made if c.id}
        for result in request.tool_results:
            head = _EVIDENCE_ID.match(result.text.lstrip("[ "))
            call = calls.get(result.id)
            if head and call is not None:
                out.setdefault(head.group(0), {"tool": call.name, "args": dict(call.args)})
    return out


def _places(text: str) -> set[int]:
    """Every place ``text`` spells, as a number."""
    return {int(m.group(1) or m.group(2), 16) for m in _PLACE.finditer(text)}


def holds_code(answer: str) -> bool:
    """Whether a listing answer holds code: one line read as more than an error or ``invalid``."""
    text = answer.strip()
    if not text or _ERROR_WORDS.match(text):
        return False
    for line in text.splitlines():
        rest = _LINE_ADDRESS.sub("", line, count=1).strip()
        words = rest.split()
        if words and words[0].lower() != "invalid" and re.search(r"[A-Za-z]{2,}", rest):
            return True
    return False


def code_evidence(record: RunRecord, dump_dir: Path | None, entries: list[Entry]) -> dict[str, Any]:
    """Which of ``entries`` are code read at a function start the same source listed.

    Function starts are the places in the answers of the source's entries
    that list functions or entry points: a declared kind naming functions or
    entry points (and not code), or, undeclared, a tool name saying so whose
    call took no place. A code entry (a declared code kind, or undeclared with
    a code-listing figure kind) counts when its answer holds code and the place
    its call was given is one of those starts.
    """
    answers = answers_of(record)
    calls = calls_by_entry(dump_dir)
    starts: set[int] = set()
    code: list[str] = []
    for entry in entries:
        if not entry.get("ok"):
            continue
        ident = str(entry.get("id"))
        kind = str((entry.get("facts") or {}).get("kind") or "")
        call = calls.get(ident) or {}
        took_place = any(_places(str(v)) for v in (call.get("args") or {}).values())
        if kind in CODE_KINDS:
            code.append(ident)
        elif kind:
            if _LISTS_FUNCTIONS.search(kind) and not took_place:
                starts |= _places(answers.get(ident, ""))
        elif _LISTS_FUNCTIONS.search(str(entry.get("tool") or "")) and not took_place:
            starts |= _places(answers.get(ident, ""))
    credited: list[str] = []
    refused: dict[str, str] = {}
    for ident in code:
        held = calls.get(ident)
        at: set[int] = set()
        for value in (held or {}).get("args", {}).values():
            at |= _places(str(value))
        if held is None:
            refused[ident] = "its call's arguments are not in the dumped requests"
        elif not holds_code(answers.get(ident, "")):
            refused[ident] = "its answer holds no code"
        elif not at & starts:
            refused[ident] = "its place is not a function start an answer listed"
        else:
            credited.append(ident)
    return {
        "function_starts": sorted(f"0x{p:x}" for p in starts),
        "code_entries": code,
        "credited": credited,
        "refused": refused,
    }


def offers(dump_dir: Path | None, role: str = "analyst") -> list[dict[str, str]]:
    """Each request the stub answered as ``role``: its offered tool names and their descriptions."""
    out: list[dict[str, str]] = []
    if dump_dir is None or not Path(dump_dir).is_dir():
        return out
    for path in sorted(Path(dump_dir).glob(f"*-{role}.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        request = wire.read_anthropic(body) if "system" in body else wire.read_openai(body)
        out.append({str(t.get("name")): str(t.get("description") or "") for t in request.tools})
    return out


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


def _asserted(record: RunRecord, entries: list[Entry], answers: dict[str, str]) -> dict[str, bool]:
    """Each source that asserted, and whether corroboration counts it among ``asserted_by``.

    A source asserts when one of its entries is declared to assert techniques
    and its answer names one (an ATT&CK id); an entry that names none asserted
    nothing, and is not held to ``asserted_by``.
    """
    sayers = {
        str(s)
        for row in (record.run_summary.get("corroboration") or {}).values()
        if isinstance(row, dict)
        for s in row.get("asserted_by") or []
    }
    out: dict[str, bool] = {}
    for entry in entries:
        facts = entry.get("facts") or {}
        if facts.get("asserts_techniques") and _TECHNIQUE_ID.search(
            answers.get(str(entry.get("id")), "")
        ):
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
    expect_cited: bool = True,
) -> dict[str, Any]:
    """The E1–E6 readings for ``server_key``'s entries (or ``match``'s) in this run.

    ``expect_cited``: the scenario expects a claim to cite the source, so E3
    misses when none does.
    """
    entries = entries_of(record, match or by_server(server_key))
    ids = [str(e.get("id")) for e in entries]
    ok_ids = [str(e.get("id")) for e in entries if e.get("ok")]
    answers = answers_of(record)
    mr = record.malware_report

    e1 = {
        "ok": bool(ok_ids),
        "why": "" if ok_ids else "no entry filed ok",
        "entries": ids,
        "ok_entries": ok_ids,
    }

    citing = claims_citing(record, ok_ids)
    cited = sorted({i for c in citing for i in c["cites"]})
    e2 = {
        "ok": bool(cited),
        "why": "" if cited else "no claim in force cites an entry",
        "cited": cited,
        "claims": [c.get("claim", "") for c in citing],
    }

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
    declared = {
        str(e.get("id")) for e in entries if e.get("ok") and (e.get("facts") or {}).get("kind")
    }
    asserted = _asserted(record, [e for e in entries if str(e.get("id")) in declared], answers)

    def names_technique(claim: dict[str, Any]) -> bool:
        return str(claim.get("technique_id") or claim.get("technique") or "").upper() not in (
            "",
            "NONE",
        )

    # Corroboration is kept per technique: its rule holds only the declared
    # entries whose kind asserts techniques and that a claim naming a
    # technique cites; every other entry is held to citation and flags only.
    asserting = {
        str(e.get("id"))
        for e in entries
        if str(e.get("id")) in declared
        and (
            (e.get("facts") or {}).get("asserts_techniques")
            or (e.get("facts") or {}).get("techniques")
        )
    }
    held = {i for c in citing if names_technique(c) for i in c["cites"]} & asserting
    held_listed = set(listed) & held
    e3_why = []
    if expect_cited and not citing:
        e3_why.append("no claim cites an entry")
    if flagged:
        e3_why.append("a claim citing it is flagged for grounding or citation")
    if not held:
        corroboration = (
            "n/a (kind asserts no technique)"
            if not asserting
            else "n/a (no claim citing an asserting entry names a technique)"
        )
    elif not held_listed:
        corroboration = "missed"
        e3_why.append("an asserting entry cited for a technique never reaches corroboration")
    elif not set(placed) & held:
        corroboration = "missed"
        e3_why.append("an asserting entry cited for a technique is not placed in corroboration")
    else:
        corroboration = "reached"
    if any(not ok for ok in asserted.values()):
        e3_why.append("an asserting declared source is not among asserted_by")
    e3 = {
        "ok": not e3_why,
        "why": "; ".join(e3_why),
        "flagged": flagged,
        "placed": placed,
        "unplaced": unplaced,
        "declared": sorted(declared),
        "corroboration": corroboration,
        "held_to_corroboration": sorted(held),
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
    e4 = {
        "ok": bool(sections_seen),
        "why": "" if sections_seen else "no composer section request holds an entry",
        "sections": sections_seen,
    }

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
    drawn = [html.unescape(str(f.get("content") or "")) for f in listings]
    own_heads = [answers.get(i, "").strip()[:40] for i in ok_ids if answers.get(i, "").strip()]
    listing_from_source = any(
        head and head.split("\n", 1)[0] in text for text in drawn for head in own_heads
    )
    # A figure drawn from an answer this source filed as failed: an error shown as code.
    failed_ids = [i for i in ids if i not in set(ok_ids)]
    failed_drawn = sorted(
        i
        for i in failed_ids
        if (head := answers.get(i, "").strip()[:60]) and any(head in text for text in drawn)
    )
    examined_ids = {
        str(i)
        for s in mr.get("sections") or []
        if isinstance(s, dict) and s.get("key") == "functions_examined"
        for i in s.get("evidence_ids") or []
    }
    functions_examined = bool(examined_ids & set(ok_ids))
    code = code_evidence(record, dump_dir, entries)
    reputation_rows = [
        r
        for r in mr.get("reputation") or []
        if isinstance(r, dict) and str(r.get("entry_id") or "") in set(ok_ids)
    ]
    e5_why = []
    if not report_sections:
        e5_why.append("no report section lists an entry")
    if not appendix:
        e5_why.append("Appendix A lists no entry")
    e5 = {
        "ok": not e5_why,
        "why": "; ".join(e5_why),
        "sections": report_sections,
        "appendix": appendix,
        "code_listing_figures": len(listings),
        "listing_from_source": listing_from_source,
        "functions_examined": functions_examined,
        # "Functions examined" cites a code entry credited as code at a function start.
        "functions_examined_by_code": bool(examined_ids & set(code["credited"])),
        "functions_examined_ids": sorted(examined_ids & set(ids)),
        "code": code,
        "reputation_rows": reputation_rows,
    }

    degradations = [str(d) for d in mr.get("degradation_reasons") or []]
    naming = [
        d for d in degradations if server_key and server_key in d and "unavailable" in d.lower()
    ]
    named_absent = absent_names(record, absent)
    suspect = [i for i in ok_ids if _ERROR_WORDS.match(answers.get(i, ""))]
    e6_why = [
        why
        for why, held in (
            ("a degradation names it unavailable", naming),
            (f"published text names {sorted(named_absent)}", named_absent),
            ("an entry filed ok reads as an error", suspect),
            ("a figure draws an answer filed as failed", failed_drawn),
        )
        if held
    ]
    e6 = {
        "ok": not e6_why,
        "why": "; ".join(e6_why),
        "degradations_naming": naming,
        "absent_named": named_absent,
        "ok_but_reads_as_error": suspect,
        "failed_answer_drawn_as_listing": failed_drawn,
    }
    return {"server": server_key, "E1": e1, "E2": e2, "E3": e3, "E4": e4, "E5": e5, "E6": e6}


def reach_markdown(rows: list[dict[str, Any]]) -> str:
    """A table of reach readings, one row per source."""
    lines = ["| Source | E1 | E2 | E3 | E4 | E5 | E6 |", "|---|---|---|---|---|---|---|"]
    for row in rows:
        marks = ["yes" if row[e]["ok"] else "NO" for e in ("E1", "E2", "E3", "E4", "E5", "E6")]
        lines.append(f"| {row['server']} | " + " | ".join(marks) + " |")
    return "\n".join(lines)
