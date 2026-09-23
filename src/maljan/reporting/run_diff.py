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

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.schemas.evidence import ENTRY_ID_RE

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

# What a row repeated inside one run says. The first row of a key is paired;
# a second row with the same key in the same run has nothing to pair with.
REPEATED_KEY_NOTE = "this key appears more than once in this run's record; only the first is paired"

# The rule-match sections the report builds from the rule tools' ledger rows,
# the engine each belongs to, and the columns compared on a pair. ``Where`` and
# ``Matched fields`` say where a rule matched, which is not a fact about which
# rule matched, and are left out of the comparison.
DETECTION_SECTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "yara_matches": ("yara", ("Tags",)),
    "sigma_matches": ("sigma", ("Level", "Technique")),
    "capa_capabilities": ("capa", ("Namespace", "ATT&CK")),
}

# Indicator kinds whose value is compared without regard to case. A URL's path
# is case-sensitive and a registry path or a mutex name is the sample's own
# spelling, so those are compared as written.
_CASELESS_INDICATOR_KINDS = frozenset(
    {"domain", "email", "hash", "ip", "ipv4", "ipv6", "sha256", "sha1", "md5", "sha512"}
)

# STIX types keyed by their ``name``, compared without regard to case.
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
# STIX observables keyed by ``value``.
_STIX_VALUE_TYPES = frozenset(
    {"domain-name", "ipv4-addr", "ipv6-addr", "url", "email-addr", "mac-addr"}
)
# Objects whose id the standard itself fixes, so the id is the key.
_STIX_ID_KEYED_TYPES = frozenset({"marking-definition", "extension-definition"})

# The properties compared on a paired STIX object. The key properties are not
# listed: they are equal by construction. Timestamps and ids differ on every
# run and are not a change in what the record says.
_STIX_COMPARED = (
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
    "indicators": "the indicator kind and value (consolidated_iocs.kind or .type, and .value)",
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
        "and a relationship to one, has no stable key and is listed by run"
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


# ── Small readers ────────────────────────────────────────────────────────────


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _evidence(*sources: Any) -> list[str]:
    """The ledger entry ids written anywhere in ``sources``, in order, once each."""
    seen: dict[str, None] = {}

    def visit(value: Any) -> None:
        if isinstance(value, str):
            for found in ENTRY_ID_RE.findall(value):
                seen.setdefault(found.lower(), None)
        elif isinstance(value, list | tuple):
            for item in value:
                visit(item)

    for source in sources:
        visit(source)
    return list(seen)


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


def _index(items: Iterable[_Item]) -> tuple[dict[str, _Item], list[_Item]]:
    first: dict[str, _Item] = {}
    repeated: list[_Item] = []
    for item in items:
        if item.key in first:
            repeated.append(item)
        else:
            first[item.key] = item
    return first, repeated


def _pair(
    items_a: Iterable[_Item],
    items_b: Iterable[_Item],
    *,
    unmatched_a: str = REMOVED,
    unmatched_b: str = ADDED,
) -> list[dict[str, Any]]:
    """Rows paired by key: one dictionary per side, one lookup per row."""
    index_a, repeated_a = _index(items_a)
    index_b, repeated_b = _index(items_b)
    rows: list[dict[str, Any]] = []
    for key, a in index_a.items():
        b = index_b.get(key)
        if b is None:
            rows.append(_row(unmatched_a, a, None))
            continue
        names = list(a.fields) + [name for name in b.fields if name not in a.fields]
        changes = [
            {"field": name, "a": a.fields.get(name), "b": b.fields.get(name)}
            for name in names
            if a.fields.get(name) != b.fields.get(name)
        ]
        rows.append(_row(CHANGED if changes else UNCHANGED, a, b, changes))
    for key, b in index_b.items():
        if key not in index_a:
            rows.append(_row(unmatched_b, None, b))
    rows.extend(_row(ONLY_IN_A, item, None, note=REPEATED_KEY_NOTE) for item in repeated_a)
    rows.extend(_row(ONLY_IN_B, None, item, note=REPEATED_KEY_NOTE) for item in repeated_b)
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
    attribution = _map(mr.get("attribution"))
    family = attribution.get("family")
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
        ),
        _Item(
            "severity",
            "Severity",
            {"value": severity, "stated_by": "judge" if severity is not None else None},
        ),
        _Item(
            "family",
            "Family",
            {
                "value": family,
                "stated_by": attribution.get("family_source"),
                "grounded": attribution.get("family_grounded") if family else None,
            },
            _evidence(_list(attribution.get("family_evidence_ids"))),
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
                _evidence(_list(cell.get("evidence")), _list(row.get("evidence_quotes"))),
            )
        )
    return items


def _indicator_key(kind: str, value: str) -> str:
    return f"{kind}|{value.lower() if kind in _CASELESS_INDICATOR_KINDS else value}"


def _indicator_items(run: RunRecord) -> tuple[list[_Item], bool, str | None]:
    """The indicator rows, whether the run recorded any, and a note on the source read."""
    mr = _map(run.malware_report)
    consolidated = _list(mr.get("consolidated_iocs"))
    items: list[_Item] = []
    if consolidated:
        for raw in consolidated:
            row = _map(raw)
            value = _text(row.get("value"))
            kind = (_text(row.get("kind")) or _text(row.get("type"))).lower()
            if not value or not kind:
                continue
            items.append(
                _Item(
                    _indicator_key(kind, value),
                    f"{kind}: {value}",
                    {
                        "type": _text(row.get("type")) or None,
                        "published": row.get("published"),
                        "source": row.get("source"),
                    },
                    _evidence(row.get("context"), row.get("description")),
                )
            )
        return items, True, None
    network = mr.get("network")
    if not isinstance(network, Mapping):
        return items, False, None
    for kind, collection, attr in (
        ("domain", "domains", "fqdn"),
        ("ip", "ips", "address"),
        ("url", "urls", "url"),
    ):
        for raw in _list(network.get(collection)):
            row = _map(raw)
            value = _text(row.get(attr))
            if value:
                items.append(
                    _Item(
                        _indicator_key(kind, value),
                        f"{kind}: {value}",
                        {"type": kind, "published": None, "source": row.get("source")},
                    )
                )
    return (
        items,
        True,
        "holds no consolidated indicator table; its network block is read instead, "
        "which records no publish decision",
    )


def _key_finding_items(run: RunRecord) -> list[_Item]:
    items: list[_Item] = []
    for raw in _list(_map(run.malware_report).get("key_findings")):
        row = _map(raw)
        text = _text(row.get("text"))
        if text:
            items.append(
                _Item(text, text, {"text": text}, _evidence(_list(row.get("evidence_ids"))))
            )
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
                _evidence(refs),
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
                _evidence(row.get("evidence_ref")),
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
                    _evidence(_list(row.get("evidence_refs"))),
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
                _evidence(_list(row.get("evidence_refs"))),
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
                _evidence(row.get("evidence_ref"), _list(row.get("evidence_refs"))),
            )
        )
    return items


def _capability_items(run: RunRecord) -> list[_Item]:
    static = _map(_map(run.malware_report).get("static"))
    evidence = _evidence(_list(static.get("api_capabilities_evidence_ids")))
    return [
        _Item(str(category), str(category), {"count": count}, evidence)
        for category, count in _map(static.get("api_capabilities")).items()
    ]


def _detection_items(run: RunRecord) -> tuple[list[_Item], bool]:
    items: list[_Item] = []
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
        evidence = _evidence(_list(section.get("evidence_ids")))
        for row in _list(section.get("rows")):
            cells = _list(row)
            rule = _text(cells[rule_at]) if rule_at < len(cells) else ""
            if not rule or rule == "-":
                continue
            fields = {
                name.lower(): (_text(cells[pos]) if pos < len(cells) else "") or None
                for name, pos in positions.items()
            }
            items.append(_Item(f"{engine}|{rule}", f"{engine}: {rule}", fields, evidence))
    return items, recorded


def _stix_object_key(obj: Mapping[str, Any]) -> str | None:
    """The deterministic key of one STIX object, or ``None`` when it has none."""
    kind = _text(obj.get("type"))
    if kind == "attack-pattern":
        for ref in _list(obj.get("external_references")):
            ref = _map(ref)
            if _text(ref.get("source_name")) == "mitre-attack" and _text(ref.get("external_id")):
                return f"{kind}|{_text(ref.get('external_id')).upper()}"
        name = _text(obj.get("name"))
        return f"{kind}|name:{name.lower()}" if name else None
    if kind == "indicator":
        pattern = _text(obj.get("pattern"))
        return f"{kind}|{pattern}" if pattern else None
    if kind in _STIX_NAMED_TYPES:
        name = _text(obj.get("name"))
        return f"{kind}|{name.lower()}" if name else None
    if kind in _STIX_VALUE_TYPES:
        value = _text(obj.get("value"))
        if not value:
            return None
        return f"{kind}|{value if kind == 'url' else value.lower()}"
    if kind == "file":
        hashes = _map(obj.get("hashes"))
        digest = _text(hashes.get("SHA-256") or hashes.get("sha256"))
        if digest:
            return f"{kind}|sha256:{digest.lower()}"
        name = _text(obj.get("name"))
        return f"{kind}|name:{name}" if name else None
    if kind == "windows-registry-key":
        key = _text(obj.get("key"))
        return f"{kind}|{key.lower()}" if key else None
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
        evidence = _evidence(_list(obj.get("x_maljan_evidence_refs")))
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
            unkeyed.append(_Item(f"{kind}|{oid}", label, {"type": kind, **fields}, evidence))
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

    ind_a, rec_a, note_a = _indicator_items(a)
    ind_b, rec_b, note_b = _indicator_items(b)
    ind_notes = [f"Run {side} {note}." for side, note in (("A", note_a), ("B", note_b)) if note]
    sections.append(
        _section(
            "indicators",
            "Indicators",
            "Indicators",
            _pair(ind_a, ind_b),
            recorded=(rec_a, rec_b),
            notes=ind_notes,
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
        ("capability_profile", "Capability profile", _capability_items),
    ):
        sections.append(_diff(key, "Findings", title, read, a, b, recorded=reports))

    det_a, det_rec_a = _detection_items(a)
    det_b, det_rec_b = _detection_items(b)
    sections.append(
        _section(
            "detection",
            "Detection",
            "Detection rule matches",
            _pair(det_a, det_b),
            recorded=(det_rec_a, det_rec_b),
        )
    )

    keyed_a, unkeyed_a, stix_a = _stix_items(a)
    keyed_b, unkeyed_b, stix_b = _stix_items(b)
    stix_rows = _pair(keyed_a, keyed_b)
    stix_rows.extend(_row(ONLY_IN_A, item, None) for item in unkeyed_a)
    stix_rows.extend(_row(ONLY_IN_B, None, item) for item in unkeyed_b)
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
