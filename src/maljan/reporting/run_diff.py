"""What changed between two stored analyses, read off their records.

An analyst who sees a sample again — the same file re-run, a new build of the
same family, a different model or team — wants to know what the second record
says that the first did not. This module answers that from the two stored
records alone: the report row's columns, its ``MalwareReport`` document, its
run summary, its exported STIX bundle and its per-agent findings.

It states what each run's record says. It never judges which run is right,
never merges the two and never writes into either: the answer is a new
document, and both inputs are only read.

Every section pairs rows by a key the record already carries, and the key is
named in the section's ``match_key``. A row the record does not key stably —
a key finding, which is prose; a STIX object whose type has no identifying
property — is never paired by resemblance: when the exact text or the key is
not in the other run, it is listed as present in one run only, which is a
different statement from "added" or "removed".

The work is linear in the two records' sizes: each side is indexed once into
a dictionary and the other side is looked up in it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# ── Row statuses ─────────────────────────────────────────────────────────────

ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"
UNCHANGED = "unchanged"
# A row whose record carries no stable key and whose exact text is not in the
# other run. Not "removed": nothing says the other run's rows are not the same
# finding written differently, and nothing here guesses.
ONLY_IN_A = "only_in_a"
ONLY_IN_B = "only_in_b"

STATUSES: tuple[str, ...] = (ADDED, REMOVED, CHANGED, UNCHANGED, ONLY_IN_A, ONLY_IN_B)

# What a row under a repeated key says when it is left unpaired. Rows under
# one key pair as a multiset, identical rows first; a single row left on each
# side pairs as changed; any other remainder is listed as removed and added
# with this note, because the record states no correspondence between them.
REPEATED_KEY_NOTE = (
    "a repeat: this key appears more than once, and the record states no correspondence "
    "between this row and the other run's rows under it"
)

# What a verdict-section row says when only who stated it differs.
READING_NOTE = (
    "who stated the {what} differs because the verdict reading does; that difference is "
    "counted once, on the Verdict row, and the {what} itself is compared here"
)

# What the indicator section says when the two runs store indicators in two
# shapes. Neither is translated into the other: a type label is not a kind,
# and turning a defanged value back into a live one is a guess.
INDICATOR_SHAPE_NOTE = (
    "The two runs store indicators differently: run {side}'s table has no kind column (a "
    "report stored before it existed, whose network values may be stored defanged). Rows of "
    "different shapes are not paired; each is listed by run."
)

# The rule-match sections the report builds from the rule tools' ledger rows,
# the engine each belongs to, and the columns compared on a pair. ``Where`` and
# ``Matched fields`` say where a rule matched, which is not a fact about which
# rule matched, and are left out of the comparison.
DETECTION_SECTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "yara_matches": ("yara", ("Tags",)),
    "sigma_matches": ("sigma", ("Level", "Technique")),
    "capa_capabilities": ("capa", ("Namespace", "ATT&CK")),
}

# The one case rule, applied to indicator values and STIX keys alike: a value
# is compared without regard to case only where it is case-insensitive by
# definition. A domain name (DNS), an IP address and a hash or a MAC address
# (hexadecimal) and a Windows registry key are; an e-mail address is in its
# domain part only. Everything else — a URL, a path, a mutex name, a malware
# or tool name — is compared as written.
CASELESS_KINDS = frozenset(
    {"domain", "ip", "ipv4", "ipv6", "hash", "md5", "sha1", "sha256", "sha512", "mac", "registry"}
)

# The indicator kind each keyed STIX observable type is read as.
_STIX_VALUE_KINDS = {
    "domain-name": "domain",
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "email-addr": "email",
    "mac-addr": "mac",
    "url": "url",
}

# A ledger entry id, the whole of a structured id item and nothing else.
_ENTRY_ID = re.compile(r"ev_\d{3,}", re.IGNORECASE)

# STIX types keyed by their ``name``, compared as written.
_STIX_NAMED_TYPES = frozenset(
    {
        "malware",
        "tool",
        "threat-actor",
        "intrusion-set",
        "campaign",
        "infrastructure",
        "identity",
        "vulnerability",
        "course-of-action",
        "location",
        "mutex",
        "malware-analysis",
    }
)
# Objects whose id the standard itself fixes, so the id is the key.
_STIX_ID_KEYED_TYPES = frozenset({"marking-definition", "extension-definition"})

# The properties compared on a paired STIX object. The key properties are not
# listed: they are equal by construction. Timestamps and ids differ on every
# run and are not a change in what the record says.
_STIX_COMPARED = (
    "name",
    "confidence",
    "x_maljan_confidence",
    "labels",
    "indicator_types",
    "malware_types",
    "is_family",
    "tool_types",
    "infrastructure_types",
    "count",
)

# What each section pairs its rows by, in the words the API docs and the
# console print.
MATCH_KEYS: dict[str, str] = {
    "verdict": "the field name",
    "attack": "the technique id (ttp_mappings.technique_id)",
    "indicators": (
        "the indicator kind and value (consolidated_iocs.kind and .value); a row stored "
        "without a kind is keyed by its type and value as stored and pairs only with rows "
        "of the same shape"
    ),
    "key_findings": "the exact text of the finding; nothing is paired by resemblance",
    "analysts": "the agent name (agent_findings.agent_name)",
    "persistence": "the mechanism kind and target (persistence.kind, .target)",
    "configuration": "the configuration key (technical_analysis.configuration.key)",
    "commands": "the command id, or its name when it has none",
    "c2_channels": "the channel name (c2_channels.name)",
    "capability_profile": "the behaviour category (static.api_capabilities)",
    "detection": "the engine and the rule name (the Rule column of each rule-match section)",
    "stix": (
        "the STIX type and a key from the object's identifying property: the ATT&CK id "
        "for an attack-pattern, the pattern for an indicator, the name for a named object, "
        "the value for an address or a URL, the SHA-256 or the name for a file, the key "
        "for a registry key, the path for a directory; a relationship by its type and the "
        "keys of both ends, a sighting by the key of what it sights. Any other object, "
        "and a relationship to one, has no stable key: it pairs only with an identical "
        "object, id included, and is otherwise listed by run"
    ),
    "run": "the fact name",
    "tools": "the tool name (run_summary.evidence.by_tool)",
    "degradation": "the exact text of the reason; nothing is paired by resemblance",
}


@dataclass(frozen=True)
class RunRecord:
    """One stored analysis, as the diff reads it.

    Every field is what the store holds, unchanged. ``sample_sha256`` is the
    sample row's digest when the caller has it; the report's own identity
    block is read when it does not.
    """

    report_id: str
    job_id: str
    created_at: str | None = None
    verdict: str | None = None
    overall_confidence: float | None = None
    malware_category: str | None = None
    malware_report: Mapping[str, Any] | None = None
    run_summary: Mapping[str, Any] | None = None
    stix_bundle: Mapping[str, Any] | None = None
    agent_findings: Sequence[Mapping[str, Any]] = ()
    sample_sha256: str | None = None
    sample_file_name: str | None = None
    duration_seconds: float | None = None


@dataclass
class _Item:
    """One row of one run, before pairing."""

    key: str
    label: str
    fields: dict[str, Any]
    evidence: list[str] = field(default_factory=list)
    # Fields shown on the row but not compared, because they follow from a
    # fact another row already compares; comparing them again would count one
    # difference in the record twice.
    derived: frozenset[str] = frozenset()
    # Said on the row when a derived field differs between the two runs.
    derived_note: str | None = None


# ── Small readers ────────────────────────────────────────────────────────────


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _ids(*sources: Any) -> list[str]:
    """Ledger entry ids from structured id fields, in order, once each.

    Only a field that *is* an id is read: a list of ids, or a citation string
    in the ``[ev_0002]`` / ``ev_0002, ev_0005`` convention. Each item must be an
    entry id and nothing else. An id written inside a sentence, a quote, a note
    or a sample's own command line is not a citation of this row, and a field
    holding anything but ids yields none.
    """
    seen: dict[str, None] = {}

    def visit(value: Any) -> None:
        if isinstance(value, str):
            for part in value.strip().strip("[]").split(","):
                token = part.strip().strip("[]").strip()
                if _ENTRY_ID.fullmatch(token):
                    seen.setdefault(token.lower(), None)
        elif isinstance(value, list | tuple):
            for item in value:
                visit(item)

    for source in sources:
        visit(source)
    return list(seen)


def canonical_value(kind: str, value: str) -> str:
    """``value`` as compared under the one case rule (see ``CASELESS_KINDS``)."""
    if kind in CASELESS_KINDS:
        return value.lower()
    if kind == "email":
        local, at, domain = value.rpartition("@")
        return f"{local}@{domain.lower()}" if at else value
    return value


def _fingerprint(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _row(
    status: str,
    item_a: _Item | None,
    item_b: _Item | None,
    changes: list[dict[str, Any]] | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    first = item_a or item_b
    assert first is not None  # noqa: S101 - a row always has one side
    return {
        "key": first.key,
        "label": first.label if item_a is None or item_b is None else item_b.label,
        "status": status,
        "a": item_a.fields if item_a is not None else None,
        "b": item_b.fields if item_b is not None else None,
        "changes": changes or [],
        "evidence": {
            "a": item_a.evidence if item_a is not None else [],
            "b": item_b.evidence if item_b is not None else [],
        },
        "note": note,
    }


def _compared(item: _Item) -> dict[str, Any]:
    return {name: value for name, value in item.fields.items() if name not in item.derived}


def _changes(a: _Item, b: _Item) -> list[dict[str, Any]]:
    fa, fb = _compared(a), _compared(b)
    names = list(fa) + [name for name in fb if name not in fa]
    return [
        {"field": name, "a": fa.get(name), "b": fb.get(name)}
        for name in names
        if fa.get(name) != fb.get(name)
    ]


def _derived_note(a: _Item, b: _Item) -> str | None:
    """The note a paired row carries when a field it does not compare differs."""
    names = a.derived | b.derived
    if any(a.fields.get(name) != b.fields.get(name) for name in names):
        return a.derived_note or b.derived_note
    return None


def _pair_key(
    occ_a: list[_Item], occ_b: list[_Item], unmatched_a: str, unmatched_b: str
) -> list[dict[str, Any]]:
    """The rows of one key, paired as a multiset.

    Identical rows pair first, as unchanged. What is left pairs as changed
    only when exactly one row is left on each side, which is ordinary one-to-one
    pairing by key. Any other remainder has no correspondence the record
    states — pairing it would follow the order the rows were stored in — so it
    is listed as removed and added with the repeat note. A key the other run
    does not hold at all takes the section's unmatched status. The answer does
    not depend on the order of either run's rows.
    """
    if not occ_b:
        return [_row(unmatched_a, a, None) for a in occ_a]
    if not occ_a:
        return [_row(unmatched_b, None, b) for b in occ_b]
    pool: dict[str, list[int]] = {}
    for index, b in enumerate(occ_b):
        pool.setdefault(_fingerprint(_compared(b)), []).append(index)
    used: set[int] = set()
    rows: list[dict[str, Any]] = []
    rest_a: list[_Item] = []
    for a in occ_a:
        same = pool.get(_fingerprint(_compared(a)))
        if same:
            index = same.pop(0)
            used.add(index)
            b = occ_b[index]
            rows.append(_row(UNCHANGED, a, b, note=_derived_note(a, b)))
        else:
            rest_a.append(a)
    rest_b = [b for index, b in enumerate(occ_b) if index not in used]
    if len(rest_a) == 1 and len(rest_b) == 1:
        a, b = rest_a[0], rest_b[0]
        rows.append(_row(CHANGED, a, b, _changes(a, b), note=_derived_note(a, b)))
        return rows
    rows.extend(_row(REMOVED, a, None, note=REPEATED_KEY_NOTE) for a in rest_a)
    rows.extend(_row(ADDED, None, b, note=REPEATED_KEY_NOTE) for b in rest_b)
    return rows


def _pair(
    items_a: Iterable[_Item],
    items_b: Iterable[_Item],
    *,
    unmatched_a: str = REMOVED,
    unmatched_b: str = ADDED,
) -> list[dict[str, Any]]:
    """Rows paired by key: one dictionary per side, one lookup per key."""
    groups_a: dict[str, list[_Item]] = {}
    for item in items_a:
        groups_a.setdefault(item.key, []).append(item)
    groups_b: dict[str, list[_Item]] = {}
    for item in items_b:
        groups_b.setdefault(item.key, []).append(item)
    rows: list[dict[str, Any]] = []
    for key, occ_a in groups_a.items():
        rows.extend(_pair_key(occ_a, groups_b.get(key, []), unmatched_a, unmatched_b))
    for key, occ_b in groups_b.items():
        if key not in groups_a:
            rows.extend(_pair_key([], occ_b, unmatched_a, unmatched_b))
    return rows


def _section(
    key: str,
    group: str,
    title: str,
    rows: list[dict[str, Any]],
    *,
    keyed: bool = True,
    recorded: tuple[bool, bool] = (True, True),
    notes: Iterable[str] = (),
    evidence: tuple[list[str], list[str]] = ([], []),
) -> dict[str, Any]:
    counts = dict.fromkeys(STATUSES, 0)
    for row in rows:
        counts[row["status"]] += 1
    out_notes = list(notes)
    for side, held in zip(("A", "B"), recorded, strict=True):
        if not held:
            out_notes.append(
                f"Run {side}'s record holds nothing for this section, so every row of the "
                "other run is listed against an absence rather than against an empty list."
            )
    return {
        "key": key,
        "group": group,
        "title": title,
        "match_key": MATCH_KEYS[key],
        "keyed": keyed,
        "recorded": {"a": recorded[0], "b": recorded[1]},
        "counts": counts,
        "rows": rows,
        "notes": out_notes,
        # Ids the record cites for the section as a whole rather than for one
        # row: the rule-match and capability-profile sections carry them.
        "section_evidence": {"a": list(evidence[0]), "b": list(evidence[1])},
    }


# ── Per-section readers ──────────────────────────────────────────────────────


def _verdict_items(run: RunRecord) -> list[_Item]:
    mr = _map(run.malware_report)
    summary = _map(run.run_summary)
    reading = _text(summary.get("verdict_reading")) or None
    # The report row's columns are what every other surface prints; the
    # document's own fields stand in only for a record that has no row.
    verdict: Any
    confidence: Any
    if run.verdict is not None:
        verdict, confidence = run.verdict, run.overall_confidence
    else:
        verdict, confidence = mr.get("verdict"), mr.get("overall_confidence")
    severity = _map(mr.get("severity")).get("rating") if mr.get("severity") else None
    # Severity is the judge's own rating only in a report built after the
    # builder stopped computing one; a report stored before carries a rating
    # no model stated. ``verdict_reading`` arrived after that change, so a
    # record holding it shows who stated the severity. A record without it
    # cannot show it, and the field is left out.
    severity_fields: dict[str, Any] = {"value": severity}
    if severity is not None and reading is not None:
        severity_fields["stated_by"] = "judge"
    attribution = _map(mr.get("attribution"))
    family = attribution.get("family")
    # Who stated the confidence and the severity follows from the verdict
    # reading, which the verdict row already compares. Shown, not compared.
    from_reading = frozenset({"stated_by"})
    return [
        _Item("verdict", "Verdict", {"value": verdict, "reading": reading}),
        _Item(
            "confidence",
            "Confidence",
            {
                "value": confidence,
                # A confidence the pipeline publishes is the judge's own number
                # on a verdict it stated, and none otherwise.
                "stated_by": "judge" if reading == "stated" and confidence is not None else None,
            },
            derived=from_reading,
            derived_note=READING_NOTE.format(what="confidence"),
        ),
        _Item(
            "severity",
            "Severity",
            severity_fields,
            derived=from_reading,
            derived_note=READING_NOTE.format(what="severity"),
        ),
        _Item(
            "family",
            "Family",
            {
                "value": family,
                "stated_by": attribution.get("family_source"),
                "grounded": attribution.get("family_grounded") if family else None,
            },
            _ids(_list(attribution.get("family_evidence_ids"))),
        ),
        _Item(
            "category",
            "Category",
            {"value": run.malware_category if run.malware_category else mr.get("malware_category")},
        ),
    ]


def _attack_items(run: RunRecord) -> list[_Item]:
    mr = _map(run.malware_report)
    cells: dict[str, Mapping[str, Any]] = {}
    for cell in _list(mr.get("capability_matrix")):
        tid = _text(_map(cell).get("technique_id")).upper()
        if tid and tid not in cells:
            cells[tid] = _map(cell)
    items: list[_Item] = []
    for raw in _list(mr.get("ttp_mappings")):
        row = _map(raw)
        tid = _text(row.get("technique_id")).upper()
        if not tid:
            continue
        cell = cells.get(tid, {})
        name = _text(row.get("technique_name"))
        items.append(
            _Item(
                tid,
                f"{tid} {name}".strip(),
                {
                    "name": name or None,
                    "tactic": _text(row.get("tactic")) or None,
                    "confidence": row.get("confidence"),
                    "confidence_source": _text(cell.get("confidence_source")) or None,
                    "corroborated": row.get("is_corroborated"),
                    "id_valid": row.get("technique_id_valid", True),
                },
                # The mapping's evidence is quoted prose, with no id field; the
                # technique's ledger ids are on its STIX objects.
            )
        )
    return items


def _indicator_items(run: RunRecord) -> tuple[list[_Item], list[_Item], bool, str | None]:
    """Rows keyed by kind, rows stored without one, whether any were recorded, and a note.

    The consolidated table has no evidence-id field, so no indicator row cites one.
    """
    mr = _map(run.malware_report)
    consolidated = _list(mr.get("consolidated_iocs"))
    by_kind: list[_Item] = []
    by_type: list[_Item] = []
    if consolidated:
        for raw in consolidated:
            row = _map(raw)
            value = _text(row.get("value"))
            kind = _text(row.get("kind")).lower()
            type_label = _text(row.get("type"))
            fields = {
                "type": type_label or None,
                "published": row.get("published"),
                "source": row.get("source"),
            }
            if not value:
                continue
            if kind:
                key = f"{kind}|{canonical_value(kind, value)}"
                by_kind.append(_Item(key, f"{kind}: {value}", fields))
            elif type_label:
                # As stored: the type label and the value, defanged or not.
                by_type.append(
                    _Item(f"type:{type_label}|{value}", f"{type_label}: {value}", fields)
                )
        return by_kind, by_type, True, None
    network = mr.get("network")
    if not isinstance(network, Mapping):
        return by_kind, by_type, False, None
    for kind, collection, attr in (
        ("domain", "domains", "fqdn"),
        ("ip", "ips", "address"),
        ("url", "urls", "url"),
    ):
        for raw in _list(network.get(collection)):
            row = _map(raw)
            value = _text(row.get(attr))
            if value:
                by_kind.append(
                    _Item(
                        f"{kind}|{canonical_value(kind, value)}",
                        f"{kind}: {value}",
                        {"type": kind, "published": None, "source": row.get("source")},
                    )
                )
    return (
        by_kind,
        by_type,
        True,
        "holds no consolidated indicator table; its network block is read instead, "
        "which records no publish decision",
    )


def _indicator_rows(
    a: tuple[list[_Item], list[_Item]], b: tuple[list[_Item], list[_Item]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Indicator rows, paired only between rows of the same key shape.

    A shape both runs hold is paired. A shape one run holds while the other run
    holds only the other shape is listed by run: the two tables say the same
    things in two vocabularies, and nothing here translates one into the other.
    A run with no indicators at all has nothing to translate, and the other
    run's rows are added or removed as usual.
    """
    rows: list[dict[str, Any]] = []
    notes: list[str] = []
    a_has = len(a[0]) + len(a[1]) > 0
    b_has = len(b[0]) + len(b[1]) > 0
    for shape, (items_a, items_b) in enumerate(zip(a, b, strict=True)):
        if items_a and items_b or not (a_has and b_has):
            rows.extend(_pair(items_a, items_b))
            continue
        rows.extend(_row(ONLY_IN_A, item, None) for item in items_a)
        rows.extend(_row(ONLY_IN_B, None, item) for item in items_b)
        if shape == 1 and (items_a or items_b):
            notes.append(INDICATOR_SHAPE_NOTE.format(side="A" if items_a else "B"))
    return rows, notes


def _key_finding_items(run: RunRecord) -> list[_Item]:
    items: list[_Item] = []
    for raw in _list(_map(run.malware_report).get("key_findings")):
        row = _map(raw)
        text = _text(row.get("text"))
        if text:
            items.append(_Item(text, text, {"text": text}, _ids(_list(row.get("evidence_ids")))))
    return items


def _analyst_items(run: RunRecord) -> list[_Item]:
    items: list[_Item] = []
    for raw in run.agent_findings:
        row = _map(raw)
        name = _text(row.get("agent_name"))
        if not name:
            continue
        claims = _list(row.get("claims"))
        refs: list[Any] = []
        for claim in claims:
            if isinstance(claim, Mapping):
                refs.append(claim.get("evidence_ref"))
                refs.append(_list(claim.get("evidence_ids")))
        items.append(
            _Item(
                name,
                name,
                {
                    "status": row.get("status"),
                    "confidence": row.get("final_confidence"),
                    "claims": len(claims),
                    "revision_rounds": row.get("revision_rounds"),
                },
                _ids(refs),
            )
        )
    return items


def _persistence_items(run: RunRecord) -> list[_Item]:
    items: list[_Item] = []
    for raw in _list(_map(run.malware_report).get("persistence")):
        row = _map(raw)
        kind, target = _text(row.get("kind")), _text(row.get("target"))
        if not target:
            continue
        items.append(
            _Item(
                f"{kind}|{target}",
                f"{kind}: {target}",
                {"technique_id": row.get("technique_id"), "payload": row.get("payload") or None},
                _ids(row.get("evidence_ref")),
            )
        )
    return items


def _technical(run: RunRecord) -> Mapping[str, Any]:
    return _map(_map(run.malware_report).get("technical_analysis"))


def _configuration_items(run: RunRecord) -> list[_Item]:
    items: list[_Item] = []
    for raw in _list(_technical(run).get("configuration")):
        row = _map(raw)
        key = _text(row.get("key"))
        if key:
            items.append(
                _Item(
                    key,
                    key,
                    {"value": row.get("value"), "how_obtained": row.get("how_obtained")},
                    _ids(_list(row.get("evidence_refs"))),
                )
            )
    return items


def _command_items(run: RunRecord) -> list[_Item]:
    items: list[_Item] = []
    for raw in _list(_technical(run).get("commands")):
        row = _map(raw)
        cid, name = _text(row.get("id")), _text(row.get("name"))
        if not cid and not name:
            continue
        items.append(
            _Item(
                f"id:{cid}" if cid else f"name:{name}",
                f"{cid} {name}".strip(),
                {"id": cid or None, "name": name or None},
                _ids(_list(row.get("evidence_refs"))),
            )
        )
    return items


def _c2_items(run: RunRecord) -> list[_Item]:
    items: list[_Item] = []
    for raw in _list(_map(run.malware_report).get("c2_channels")):
        row = _map(raw)
        name = _text(row.get("name"))
        if not name:
            continue
        items.append(
            _Item(
                name,
                name,
                {
                    "protocol": row.get("protocol"),
                    "encryption": row.get("encryption"),
                    "endpoints": sorted(_text(e) for e in _list(row.get("endpoints")) if _text(e)),
                },
                _ids(row.get("evidence_ref"), _list(row.get("evidence_refs"))),
            )
        )
    return items


def _capability_items(run: RunRecord) -> list[_Item]:
    static = _map(_map(run.malware_report).get("static"))
    return [
        _Item(str(category), str(category), {"count": count})
        for category, count in _map(static.get("api_capabilities")).items()
    ]


def _capability_evidence(run: RunRecord) -> list[str]:
    """The ids the profile as a whole was counted from; no one category's own."""
    static = _map(_map(run.malware_report).get("static"))
    return _ids(_list(static.get("api_capabilities_evidence_ids")))


def _detection_items(run: RunRecord) -> tuple[list[_Item], bool, list[str]]:
    """Rule-match rows, whether any rule section was recorded, and the sections' ids.

    A rule section cites its ledger entries as a whole, not per rule, so the
    ids are the section's and no row carries them.
    """
    items: list[_Item] = []
    evidence: list[str] = []
    recorded = False
    for raw in _list(_map(run.malware_report).get("sections")):
        section = _map(raw)
        spec = DETECTION_SECTIONS.get(_text(section.get("key")))
        if spec is None:
            continue
        recorded = True
        engine, compared = spec
        columns = [_text(c).lower() for c in _list(section.get("columns"))]
        try:
            rule_at = columns.index("rule")
        except ValueError:
            continue
        positions = {
            name: columns.index(name.lower()) for name in compared if name.lower() in columns
        }
        evidence.extend(i for i in _ids(_list(section.get("evidence_ids"))) if i not in evidence)
        for row in _list(section.get("rows")):
            cells = _list(row)
            rule = _text(cells[rule_at]) if rule_at < len(cells) else ""
            if not rule or rule == "-":
                continue
            fields = {
                name.lower(): (_text(cells[pos]) if pos < len(cells) else "") or None
                for name, pos in positions.items()
            }
            items.append(_Item(f"{engine}|{rule}", f"{engine}: {rule}", fields))
    return items, recorded, evidence


def _stix_object_key(obj: Mapping[str, Any]) -> str | None:
    """The deterministic key of one STIX object, or ``None`` when it has none."""
    kind = _text(obj.get("type"))
    if kind == "attack-pattern":
        for ref in _list(obj.get("external_references")):
            ref = _map(ref)
            if _text(ref.get("source_name")) == "mitre-attack" and _text(ref.get("external_id")):
                return f"{kind}|{_text(ref.get('external_id')).upper()}"
        name = _text(obj.get("name"))
        return f"{kind}|name:{name}" if name else None
    if kind == "indicator":
        pattern = _text(obj.get("pattern"))
        return f"{kind}|{pattern}" if pattern else None
    if kind in _STIX_NAMED_TYPES:
        name = _text(obj.get("name"))
        return f"{kind}|{name}" if name else None
    if kind in _STIX_VALUE_KINDS:
        value = _text(obj.get("value"))
        return f"{kind}|{canonical_value(_STIX_VALUE_KINDS[kind], value)}" if value else None
    if kind == "file":
        hashes = _map(obj.get("hashes"))
        digest = _text(hashes.get("SHA-256") or hashes.get("sha256"))
        if digest:
            return f"{kind}|sha256:{canonical_value('hash', digest)}"
        name = _text(obj.get("name"))
        return f"{kind}|name:{name}" if name else None
    if kind == "windows-registry-key":
        key = _text(obj.get("key"))
        return f"{kind}|{canonical_value('registry', key)}" if key else None
    if kind == "directory":
        path = _text(obj.get("path"))
        return f"{kind}|{path}" if path else None
    if kind == "autonomous-system":
        number = obj.get("number")
        return f"{kind}|{number}" if isinstance(number, int) else None
    if kind in _STIX_ID_KEYED_TYPES:
        oid = _text(obj.get("id"))
        return f"{kind}|{oid}" if oid else None
    return None


def _stix_label(obj: Mapping[str, Any]) -> str:
    kind = _text(obj.get("type")) or "object"
    for name in ("name", "value", "pattern", "key", "path"):
        text = _text(obj.get(name))
        if text:
            return f"{kind}: {text}"
    return kind


def _stix_items(run: RunRecord) -> tuple[list[_Item], list[_Item], bool]:
    """Keyed objects, objects with no stable key, and whether a bundle was recorded."""
    bundle = run.stix_bundle
    if not isinstance(bundle, Mapping):
        return [], [], False
    objects = [_map(o) for o in _list(bundle.get("objects"))]
    keys: dict[str, str | None] = {}
    for obj in objects:
        oid = _text(obj.get("id"))
        if oid and _text(obj.get("type")) not in ("relationship", "sighting"):
            keys[oid] = _stix_object_key(obj)

    labels = {
        _text(obj.get("id")): _stix_label(obj)
        for obj in objects
        if _text(obj.get("type")) not in ("relationship", "sighting")
    }
    keyed: list[_Item] = []
    unkeyed: list[_Item] = []
    for obj in objects:
        kind = _text(obj.get("type"))
        oid = _text(obj.get("id"))
        fields = {name: obj[name] for name in _STIX_COMPARED if name in obj}
        evidence = _ids(_list(obj.get("x_maljan_evidence_refs")))
        if kind == "relationship":
            src, tgt = _text(obj.get("source_ref")), _text(obj.get("target_ref"))
            rtype = _text(obj.get("relationship_type"))
            src_key, tgt_key = keys.get(src), keys.get(tgt)
            label = f"{labels.get(src, src)} {rtype} {labels.get(tgt, tgt)}"
            key = f"relationship|{rtype}|{src_key}|{tgt_key}" if src_key and tgt_key else None
        elif kind == "sighting":
            of = _text(obj.get("sighting_of_ref"))
            of_key = keys.get(of)
            label = f"sighting of {labels.get(of, of)}"
            key = f"sighting|{of_key}" if of_key else None
        else:
            key = keys.get(oid)
            label = _stix_label(obj)
        if key is None:
            # No stable key: the object pairs only with an identical one, id
            # included — which two runs never mint, and one record compared
            # with itself always holds.
            digest = hashlib.sha256(_fingerprint(obj).encode()).hexdigest()[:16]
            unkeyed.append(
                _Item(f"exact:{kind}|{digest}", label, {"type": kind, **fields}, evidence)
            )
        else:
            keyed.append(_Item(key, label, {"type": kind, **fields}, evidence))
    return keyed, unkeyed, True


def _run_fact_items(run: RunRecord) -> list[_Item]:
    summary = _map(run.run_summary)
    mr = _map(run.malware_report)
    profile = _map(summary.get("profile"))
    items = [
        _Item("profile", "Team profile", {"value": profile.get("name")}),
        _Item(
            "analysts",
            "Analysts in the profile",
            {"value": sorted(str(a) for a in _list(profile.get("analysts"))) or None},
        ),
    ]
    for agent, block in sorted(_map(summary.get("models")).items()):
        block = _map(block)
        items.append(
            _Item(
                f"models:{agent}",
                f"Models answering {agent}",
                {
                    "value": sorted(str(m) for m in _map(block.get("turns"))) or None,
                    "fallbacks": len(_list(block.get("fallbacks"))),
                },
            )
        )
    tokens = summary.get("tokens")
    if isinstance(tokens, Mapping):
        # A summary stored with estimates folded into its sums carries no
        # count, and none is shown for it.
        estimated = int(tokens.get("estimated_calls") or 0) > 0
        for name, label in (
            ("input_tokens", "Input tokens"),
            ("output_tokens", "Output tokens"),
            ("total_tokens", "Total tokens"),
            ("llm_calls", "Model calls"),
            ("unreported_calls", "Calls whose provider reported no usage"),
            ("cost", "Cost reported by the provider (USD)"),
        ):
            value = tokens.get(name)
            if estimated and name.endswith("_tokens"):
                value = None
            items.append(_Item(f"tokens:{name}", label, {"value": value}))
    items.append(
        _Item(
            "elapsed_seconds", "Pipeline wall time (s)", {"value": summary.get("elapsed_seconds")}
        )
    )
    items.append(_Item("job_duration_seconds", "Job duration (s)", {"value": run.duration_seconds}))
    degraded = mr.get("degraded_mode") if "degraded_mode" in mr else summary.get("degraded_mode")
    items.append(_Item("degraded", "Degraded run", {"value": degraded}))
    return items


def _tool_items(run: RunRecord) -> tuple[list[_Item], bool]:
    evidence = _map(run.run_summary).get("evidence")
    if not isinstance(evidence, Mapping) or not isinstance(evidence.get("by_tool"), Mapping):
        return [], False
    return [
        _Item(str(tool), str(tool), {"calls": count}) for tool, count in evidence["by_tool"].items()
    ], True


def _degradation_items(run: RunRecord) -> list[_Item]:
    mr = _map(run.malware_report)
    reasons = _list(mr.get("degradation_reasons")) or _list(
        _map(run.run_summary).get("degradation_reasons")
    )
    return [_Item(t, t, {"text": t}) for t in (_text(r) for r in reasons) if t]


# ── The diff ─────────────────────────────────────────────────────────────────


def _sha256(run: RunRecord) -> str | None:
    sha = _text(run.sample_sha256)
    if not sha:
        hashes = _map(_map(_map(run.malware_report).get("identity")).get("hashes"))
        sha = _text(hashes.get("sha256"))
    return sha.lower() or None


def _side(run: RunRecord) -> dict[str, Any]:
    identity = _map(_map(run.malware_report).get("identity"))
    return {
        "report_id": run.report_id,
        "job_id": run.job_id,
        "created_at": run.created_at,
        "sha256": _sha256(run),
        "file_name": run.sample_file_name or identity.get("file_name"),
    }


def sample_statement(sha_a: str | None, sha_b: str | None) -> tuple[bool | None, str]:
    """Whether the two runs analysed the same file, and the sentence that says so."""
    if not sha_a or not sha_b:
        missing = " and ".join(side for side, sha in (("A", sha_a), ("B", sha_b)) if not sha)
        return None, (
            f"The SHA-256 of run {missing} is not recorded, so whether both runs analysed "
            "the same file is not known."
        )
    if sha_a == sha_b:
        return True, "Both runs analysed the same file (the SHA-256 is the same)."
    return False, "The runs analysed different files (the SHA-256 differs)."


def _diff(
    key: str,
    group: str,
    title: str,
    read: Callable[[RunRecord], list[_Item]],
    a: RunRecord,
    b: RunRecord,
    **kwargs: Any,
) -> dict[str, Any]:
    return _section(key, group, title, _pair(read(a), read(b)), **kwargs)


def _has_report(run: RunRecord) -> bool:
    return isinstance(run.malware_report, Mapping)


def diff_runs(a: RunRecord, b: RunRecord) -> dict[str, Any]:
    """What run B's record says that run A's does not, and the reverse.

    Pure: it reads the two records and returns a new document. The sections
    come in a fixed order, each with its match key, its counts per status and
    its rows; a changed row names each field that differs with both values.
    """
    reports = (_has_report(a), _has_report(b))
    same, statement = sample_statement(_sha256(a), _sha256(b))
    sections: list[dict[str, Any]] = []

    sections.append(
        _diff(
            "verdict", "Verdict", "Verdict, confidence, severity and family", _verdict_items, a, b
        )
    )
    sections.append(
        _diff(
            "attack", "ATT&CK", "ATT&CK techniques published", _attack_items, a, b, recorded=reports
        )
    )

    kind_a, type_a, rec_a, note_a = _indicator_items(a)
    kind_b, type_b, rec_b, note_b = _indicator_items(b)
    ind_rows, shape_notes = _indicator_rows((kind_a, type_a), (kind_b, type_b))
    ind_notes = [f"Run {side} {note}." for side, note in (("A", note_a), ("B", note_b)) if note]
    sections.append(
        _section(
            "indicators",
            "Indicators",
            "Indicators",
            ind_rows,
            recorded=(rec_a, rec_b),
            notes=[*ind_notes, *shape_notes],
        )
    )

    sections.append(
        _section(
            "key_findings",
            "Findings",
            "Key findings",
            _pair(
                _key_finding_items(a),
                _key_finding_items(b),
                unmatched_a=ONLY_IN_A,
                unmatched_b=ONLY_IN_B,
            ),
            keyed=False,
            recorded=reports,
        )
    )
    sections.append(_diff("analysts", "Findings", "Analyst findings", _analyst_items, a, b))
    for key, title, read in (
        ("persistence", "Persistence mechanisms", _persistence_items),
        ("configuration", "Recovered configuration", _configuration_items),
        ("commands", "Commands", _command_items),
        ("c2_channels", "Command-and-control channels", _c2_items),
    ):
        sections.append(_diff(key, "Findings", title, read, a, b, recorded=reports))
    sections.append(
        _diff(
            "capability_profile",
            "Findings",
            "Capability profile",
            _capability_items,
            a,
            b,
            recorded=reports,
            evidence=(_capability_evidence(a), _capability_evidence(b)),
        )
    )

    det_a, det_rec_a, det_ev_a = _detection_items(a)
    det_b, det_rec_b, det_ev_b = _detection_items(b)
    sections.append(
        _section(
            "detection",
            "Detection",
            "Detection rule matches",
            _pair(det_a, det_b),
            recorded=(det_rec_a, det_rec_b),
            evidence=(det_ev_a, det_ev_b),
        )
    )

    keyed_a, unkeyed_a, stix_a = _stix_items(a)
    keyed_b, unkeyed_b, stix_b = _stix_items(b)
    stix_rows = _pair(keyed_a, keyed_b)
    stix_rows.extend(_pair(unkeyed_a, unkeyed_b, unmatched_a=ONLY_IN_A, unmatched_b=ONLY_IN_B))
    sections.append(_section("stix", "STIX", "STIX objects", stix_rows, recorded=(stix_a, stix_b)))

    sections.append(_diff("run", "Run", "Run facts", _run_fact_items, a, b))
    tools_a, tools_rec_a = _tool_items(a)
    tools_b, tools_rec_b = _tool_items(b)
    sections.append(
        _section(
            "tools",
            "Run",
            "Tools called",
            _pair(tools_a, tools_b),
            recorded=(tools_rec_a, tools_rec_b),
        )
    )
    sections.append(
        _section(
            "degradation",
            "Run",
            "Degradation reasons",
            _pair(
                _degradation_items(a),
                _degradation_items(b),
                unmatched_a=ONLY_IN_A,
                unmatched_b=ONLY_IN_B,
            ),
            keyed=False,
        )
    )

    totals = dict.fromkeys(STATUSES, 0)
    for section in sections:
        for status, count in section["counts"].items():
            totals[status] += count
    return {
        "a": _side(a),
        "b": _side(b),
        "same_sample": same,
        "sample_statement": statement,
        "totals": totals,
        "sections": sections,
    }
