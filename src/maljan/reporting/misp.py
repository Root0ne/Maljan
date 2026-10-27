"""MISP attributes for a report: its published indicators and techniques, in MISP's own types.

Built deterministically from two things the report already decided: the rows
of its consolidated IOC table the one publish rule publishes, and the ATT&CK
techniques it publishes. Nothing is asked again here, so the attributes carry
exactly what the IOC table, ``/reports/{id}/iocs`` and the STIX export carry:
a withheld row is never an attribute. Each indicator attribute has MISP's
standard type and category for its kind, ``to_ids`` set from the publish
decision, and a comment naming why the row is published. An imphash, an
ssdeep or a TLSH also matches files that are not the sample, so it is
published unflagged for IDS. A technique is a ``text`` attribute, tagged with
its ATT&CK galaxy cluster when the vendored ATT&CK table names it; it
describes the sample rather than matching anything, so it is not flagged for
IDS either.

One pass over the table and one over the techniques; no per-sample value is
written here.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from maljan.reporting.renderers.stix_renderer import digest_label, publishes

# The namespace each attribute's uuid is derived in, with the report's own id
# (or its job's) and the attribute's type and value: the same report always
# yields the same uuids, and two reports sharing a value yield two attributes.
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "maljan:misp-attribute")

# The IOC table's digest types, as MISP names the attribute.
_HASH_TYPES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "imphash": "imphash",
    "ssdeep": "ssdeep",
    "tlsh": "tlsh",
}

# The digest types that also match files that are not the sample.
_SIMILARITY_TYPES = frozenset({"imphash", "ssdeep", "tlsh"})

# MISP's attribute type for every other row kind the table holds. A kind MISP
# has no type for is a ``text`` attribute, typed in its comment.
_KIND_TYPES = {
    "domain": "domain",
    "ip": "ip-dst",
    "url": "url",
    "email": "email-dst",
    "user_agent": "user-agent",
    "ja3": "ja3-fingerprint-md5",
    "path": "filename",
    "registry": "regkey",
    "mutex": "mutex",
    "scheduled_task": "windows-scheduled-task",
    "service": "windows-service-name",
}

# The category of a digest, by who recorded the row: the sample's own digests
# deliver the payload, a dropped file's is an artifact, a carved file's
# installs one.
_HASH_CATEGORIES = {
    "identity": "Payload delivery",
    "sandbox": "Artifacts dropped",
    "static": "Payload installation",
}

# The category of every other type, from the categories MISP allows for it.
_TYPE_CATEGORIES = {
    "domain": "Network activity",
    "ip-dst": "Network activity",
    "url": "Network activity",
    "email-dst": "Network activity",
    "user-agent": "Network activity",
    "ja3-fingerprint-md5": "Network activity",
    "filename": "Artifacts dropped",
    "named pipe": "Artifacts dropped",
    "mutex": "Artifacts dropped",
    "windows-scheduled-task": "Artifacts dropped",
    "windows-service-name": "Artifacts dropped",
    "text": "Other",
}


# The categories MISP accepts each type written here in, from PyMISP's
# ``describeTypes.json`` (``category_type_mappings``), restricted to these
# types and to the categories this module chooses.
_ALLOWED_CATEGORIES: dict[str, frozenset[str]] = {
    "md5": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "sha1": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "sha256": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "sha512": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "imphash": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "ssdeep": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "tlsh": frozenset({"Payload delivery", "Payload installation"}),
    "filename": frozenset({"Payload delivery", "Artifacts dropped", "Persistence mechanism"}),
    "named pipe": frozenset({"Artifacts dropped"}),
    "regkey": frozenset({"Artifacts dropped", "Persistence mechanism"}),
    "mutex": frozenset({"Artifacts dropped"}),
    "windows-scheduled-task": frozenset({"Artifacts dropped"}),
    "windows-service-name": frozenset({"Artifacts dropped"}),
}

# The type a row of a kind MISP has no type for is written as; it describes
# and is never flagged for IDS.
_UNTYPED = "text"


def misp_type(row: Any) -> tuple[str, str]:
    """MISP's attribute type and category for one IOC-table row.

    A category MISP does not accept the type in is ``Payload delivery``,
    which accepts every digest and file type this module writes.
    """
    kind, category = _chosen_type(row)
    allowed = _ALLOWED_CATEGORIES.get(kind)
    if allowed is not None and category not in allowed:
        return kind, "Payload delivery"
    return kind, category


def _chosen_type(row: Any) -> tuple[str, str]:
    kind = str(getattr(row, "kind", "") or "")
    label = str(getattr(row, "type", "") or "")
    source = str(getattr(row, "source", "") or "")
    if kind == "hash":
        # The sample's own digests carry the algorithm the router computed;
        # any other digest is named by its length, and none otherwise.
        named = label if source == "identity" else digest_label(getattr(row, "value", ""))
        name = _HASH_TYPES.get(str(named or "").strip().lower().replace("-", ""), "")
        if not name:
            return "", ""
        return name, _HASH_CATEGORIES.get(source, "Payload delivery")
    if kind == "registry":
        # A key a persistence mechanism names persists the sample; a key a
        # sandbox or a string sweep recorded is an artifact of the run.
        category = "Persistence mechanism" if source == "persistence" else "Artifacts dropped"
        return "regkey", category
    if kind == "path" and label == "Named pipe":
        return "named pipe", _TYPE_CATEGORIES["named pipe"]
    name = _KIND_TYPES.get(kind, "text")
    return name, _TYPE_CATEGORIES.get(name, "Other")


def misp_owner(report: Any, job_id: Any = None) -> str:
    """What a report's attribute uuids are derived from: its job's id, else its own number."""
    front = getattr(report, "front_matter", None)
    number = str(getattr(front, "report_number", "") or "") if front is not None else ""
    hashes = getattr(getattr(report, "identity", None), "hashes", None)
    return str(job_id or number or getattr(hashes, "sha256", "") or "")


def _reason(answer: Any) -> str:
    text = str(answer or "").strip()
    return text.split(":", 1)[1].strip() if ":" in text else ""


def build_misp_attributes(
    report: Any, rows: Iterable[Any] | None = None, *, owner: str
) -> list[dict[str, Any]]:
    """The report's MISP attributes: one per published IOC-table row, then one per technique.

    ``rows`` is the report's IOC table; the stored one when not given. A row
    the publish rule withholds is not an attribute, and neither is a digest
    whose length names no algorithm. Each (type, value) is written once, in
    the table's order. ``owner`` is the report's id, or its job's, which each
    attribute's uuid is derived from.
    """
    from maljan.memory.attck_loader import technique_entry

    table = list(rows if rows is not None else getattr(report, "consolidated_iocs", None) or [])
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _attribute(kind: str, category: str, value: str, to_ids: bool, comment: str) -> dict:
        return {
            "uuid": str(uuid.uuid5(_NAMESPACE, f"{owner}|{kind}|{value}")),
            "type": kind,
            "category": category,
            "value": value,
            "to_ids": to_ids,
            "comment": comment,
        }

    for row in table:
        value = str(getattr(row, "value", "") or "").strip()
        answer = getattr(row, "published", None)
        if not value or not publishes(answer):
            continue
        kind, category = misp_type(row)
        if not kind:
            continue
        key = (kind, value.lower())
        if key in seen:
            continue
        seen.add(key)
        label = str(getattr(row, "type", "") or "")
        why = _reason(answer)
        comment = "; ".join(
            part
            for part in (
                label if kind == "text" else "",
                str(getattr(row, "context", "") or ""),
                f"published because {why}" if why else "",
            )
            if part
        )
        to_ids = publishes(answer) and kind not in _SIMILARITY_TYPES and kind != _UNTYPED
        out.append(_attribute(kind, category, value, to_ids, comment))

    techniques: set[str] = set()
    for mapping in getattr(report, "ttp_mappings", None) or []:
        tid = str(getattr(mapping, "technique_id", "") or "").strip().upper()
        if not tid or tid in techniques:
            continue
        techniques.add(tid)
        # The galaxy cluster is named as ATT&CK names the technique, from the
        # vendored table; a technique the table does not name gets no tag.
        entry = technique_entry(tid)
        canonical = str(getattr(entry, "name", "") or "").strip() if entry is not None else ""
        name = canonical or str(getattr(mapping, "technique_name", "") or "").strip()
        attribute = _attribute(
            "text",
            "External analysis",
            f"{tid} {name}" if name else tid,
            False,
            "ATT&CK technique this report publishes",
        )
        if canonical:
            attribute["Tag"] = [{"name": f'misp-galaxy:mitre-attack-pattern="{canonical} - {tid}"'}]
        out.append(attribute)
    return out
