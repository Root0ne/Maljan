"""Judge bundle post-processor.

The helpers that run after the verdict LLM returns a parsed bundle ``dict``
and before :class:`maljan.schemas.stix_models.Bundle` validation.

:func:`relate_to_the_sample` runs before the others: it writes the two
relationships the platform derives rather than asks for — the sample uses each
attack-pattern, each indicator indicates the sample — carrying the judge's own
annotations from the object they relate.

:func:`lift_misplaced_extensions` runs first and answers one question: what to
do with an item inside ``objects`` that the Bundle model cannot hold. Until
now the answer was "throw the bundle away" — one ``x_maljan_assessment``
written inside the list instead of beside it raised twenty-one validation
errors and cost a live run all twenty-five of its objects and its verdict with
them. The block is moved to the property it belongs to, unchanged; anything
else the model cannot hold is set aside; both acts are recorded and the rest
of the bundle is validated.

:func:`postprocess_judge_bundle` then applies the defensive fixes, all three
of them shape repairs:

* STIX ids — every object's id is minted here, a random UUID (a derived one
  for an attack-pattern) under the object's own type, and every
  cross-reference is rewritten to match. The judge's ids are labels that link
  its objects; the ones it copies out of documentation are neither UUIDs nor
  unique across runs.
* Reference back-fill — add ``external_references`` to each ``AttackPattern``
  SDO with the canonical MITRE ATT&CK URL when the LLM left it empty.
* Integrity pass — drop empty patterns, deduplicate, and sweep references that
  point at nothing.

The indicator corpus check is no longer here. It is a
``stix.ungrounded_indicator`` violation the judge is shown and given a turn to
fix (``pipeline.validation``); only what survives that turn is dropped, and the
drop is recorded in the run summary rather than happening quietly.
:func:`build_evidence_corpus` stays, because that check still needs a corpus.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from maljan.analysis.technique_ids import attack_reference_id
from maljan.core.logger import logger
from maljan.core.truncation_ledger import EXPORT_PASS, JUDGE_PASS
from maljan.reporting.dedupe import pattern_fingerprint

if TYPE_CHECKING:
    from maljan.pipeline.validation import Violation

# Curated technique ID → (display name, URL) map. Extend over time; the
# back-fill is best-effort and falls back to a deterministic URL when the
# technique isn't here.
_MITRE_LOOKUP: dict[str, tuple[str, str]] = {
    "T1006": ("Direct Volume Access", "https://attack.mitre.org/techniques/T1006/"),
    "T1021.001": ("Remote Desktop Protocol", "https://attack.mitre.org/techniques/T1021/001/"),
    "T1027": ("Obfuscated Files or Information", "https://attack.mitre.org/techniques/T1027/"),
    "T1036.006": ("Space after Filename", "https://attack.mitre.org/techniques/T1036/006/"),
    "T1055": ("Process Injection", "https://attack.mitre.org/techniques/T1055/"),
    "T1059.001": ("PowerShell", "https://attack.mitre.org/techniques/T1059/001/"),
    "T1071": ("Application Layer Protocol", "https://attack.mitre.org/techniques/T1071/"),
    "T1078.004": ("Cloud Accounts", "https://attack.mitre.org/techniques/T1078/004/"),
    "T1095": ("Non-Application Layer Protocol", "https://attack.mitre.org/techniques/T1095/"),
    "T1106": ("Native API", "https://attack.mitre.org/techniques/T1106/"),
    "T1140": (
        "Deobfuscate/Decode Files or Information",
        "https://attack.mitre.org/techniques/T1140/",
    ),
    "T1486": ("Data Encrypted for Impact", "https://attack.mitre.org/techniques/T1486/"),
    "T1497": ("Virtualization/Sandbox Evasion", "https://attack.mitre.org/techniques/T1497/"),
    "T1547": ("Boot or Logon Autostart Execution", "https://attack.mitre.org/techniques/T1547/"),
}


def _technique_display_name(tid: str) -> str | None:
    """Friendly ATT&CK technique name from the already-built index, else None.

    Reuses the ATTCKValidator singleton ONLY when it is already initialized —
    never forces an index build, so unit tests stay offline/fast. Fail-safe.
    Lets the reference back-fill give correct names for all ~700 techniques,
    not just the curated fallback table below.
    """
    try:
        from maljan.memory.attck_validator import ATTCKValidator

        validator = ATTCKValidator.current_instance()
        if validator is None:
            return None
        tech = validator.get_technique(tid)
        return tech.name if tech is not None else None
    except Exception:  # noqa: BLE001 — best-effort cosmetic back-fill
        return None


ASSESSMENT_RELOCATED_CODE = "verdict.assessment_relocated"

# An object inside ``objects`` that no STIX type in the bundle's union matches.
# Set aside rather than rewritten: what the judge meant by it is the judge's,
# and a bundle is not worth losing over one of them.
UNKNOWN_OBJECT_CODE = "stix.unknown_object"

# A property of a judge object that the platform's model for its type does not
# declare, so the export does not carry it. Recorded, not asked about: nothing
# is wrong with the judge's answer, and the retry is not spent on it.
PROPERTY_NOT_CARRIED_CODE = "stix.property_not_carried"

# Properties the platform's models declare because the export writes them from
# the run's record, and which a judge object therefore never carries: the
# judge's copy is recorded as not carried, like an undeclared key, and dropped.
PLATFORM_ONLY_PROPERTIES: frozenset[str] = frozenset({"x_maljan_evidence_refs"})


def _not_carried(obj: dict[str, Any]) -> list[str]:
    """The keys of a readable judge object that its model does not declare.

    A custom ``x_`` property of an observable is kept (its model allows them);
    every other undeclared key, on any type, is one the export does not carry.
    """
    from maljan.schemas.stix_models import bundle_model_for

    model = bundle_model_for(str(obj.get("type") or ""))
    if model is None:
        return []
    keeps_custom = model.model_config.get("extra") == "allow"
    return [
        key
        for key in obj
        if key in PLATFORM_ONLY_PROPERTIES
        or (key not in model.model_fields and not (keeps_custom and key.startswith("x_")))
    ]


def _object_type(obj: Any) -> str:
    return str(obj.get("type") or "").strip() if isinstance(obj, dict) else ""


# The object types the judge's bundle is for, as the sentence about a set-aside
# object names them. The bundle model holds more — the identity, report,
# observed data and notes the export mints — and naming those invited the
# judge to write objects the export builds itself.
JUDGE_OBJECT_TYPES = (
    "attack-pattern",
    "file",
    "indicator",
    "malware",
    "note",
    "process",
    "relationship",
)


def _object_problem(obj: dict[str, Any]) -> str:
    """Why one object of a bundle type cannot be read as written, or ``""``.

    A property its type does not define would be lost at validation, and a
    value the model cannot hold would fail it — and a failure there cost the
    whole bundle, the verdict with it, to the text fallback. Either is this
    object's problem alone: it is set aside with a record, and the rest of the
    answer is read.
    """
    from pydantic import ValidationError

    from maljan.pipeline.events import safe_finding_value
    from maljan.schemas.stix_models import bundle_model_for, undefined_properties

    extra = undefined_properties(obj)
    if extra:
        named = ", ".join(repr(safe_finding_value(key)) for key in extra)
        hint = (
            "; the image a process ran from is a file it names by image_ref"
            if obj.get("type") == "process" and "name" in extra
            else "; name each observable as an object of its own and list it in object_refs"
            if obj.get("type") == "observed-data"
            else ""
        )
        return f"carries {named}, which STIX 2.1 does not define for it{hint}"
    model = bundle_model_for(str(obj.get("type") or ""))
    if model is None:
        return ""
    try:
        model.model_validate(obj)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(step) for step in first.get("loc", ()) if not isinstance(step, int))
        return (
            f"does not read as one: {safe_finding_value(where or 'value')} {first.get('msg', '')}"
        )
    return ""


def lift_misplaced_extensions(bundle_dict: dict[str, Any]) -> list[Violation]:
    """Move the assessment out of ``objects``, set aside what cannot be held.

    Returns the violations this pass produced, in the order they happened. The
    first — the relocation — is a move and not an edit: the block reaches the
    bundle's own property byte for byte, and nothing about it is rewritten. It
    is recorded as resolved and costs no retry, because there is nothing left
    for the judge to fix. The second is a set-aside object, which is fed back
    once like any other violation: the model wrote something this bundle has
    no place for, and only the model can say what it meant.

    A top-level block already present wins. Two answers to one question is not
    a thing to merge, and the one the judge put where it was asked for is the
    one it meant; the inner copy is set aside and recorded beside it.
    """
    from maljan.pipeline.events import safe_finding_value
    from maljan.pipeline.validation import Violation
    from maljan.schemas.stix_models import ASSESSMENT_PROPERTY, BUNDLE_OBJECT_TYPES

    objects = bundle_dict.get("objects")
    if not isinstance(objects, list):
        return []
    found: list[Violation] = []
    kept: list[Any] = []
    for index, obj in enumerate(objects):
        kind = _object_type(obj)
        if kind in BUNDLE_OBJECT_TYPES:
            problem = _object_problem(obj)
            if not problem:
                not_carried = _not_carried(obj)
                # Dropped in place: callers key the judge's objects by identity
                # (``JudgeAgent`` maps each back to its position), and the
                # answer as the judge wrote it was copied before this runs.
                for key in PLATFORM_ONLY_PROPERTIES & set(obj):
                    del obj[key]
                kept.append(obj)
                if not_carried:
                    found.append(
                        Violation(
                            code=PROPERTY_NOT_CARRIED_CODE,
                            message=(
                                f"objects[{index}] {safe_finding_value(obj.get('id') or kind)!r} "
                                f"carries {', '.join(repr(safe_finding_value(k)) for k in not_carried)}, "
                                "which this platform does not carry into the export; they are "
                                "recorded here, and the judge's own bundle keeps them as written."
                            ),
                            path=f"objects[{index}]",
                        )
                    )
                continue
            found.append(
                Violation(
                    code=UNKNOWN_OBJECT_CODE,
                    message=(
                        f"objects[{index}] of type {safe_finding_value(kind)!r} {problem}, so it "
                        "was set aside and the rest of the bundle was read. Write it with the "
                        "properties its type defines, or leave it out."
                    ),
                    path=f"objects[{index}]",
                )
            )
            continue
        if kind == ASSESSMENT_PROPERTY and not bundle_dict.get(ASSESSMENT_PROPERTY):
            bundle_dict[ASSESSMENT_PROPERTY] = obj
            found.append(
                Violation(
                    code=ASSESSMENT_RELOCATED_CODE,
                    message=(
                        f"{ASSESSMENT_PROPERTY} was written inside objects[{index}] and belongs "
                        "beside the list; it was moved there unchanged and read from there. "
                        'Write it as a sibling of "objects" next time.'
                    ),
                    path=ASSESSMENT_PROPERTY,
                )
            )
            continue
        # The type is the model's own word and travels into a stored row, so it
        # is held to the same rule every other model-written value on this path
        # is: scrubbed, and as long as a value in a finding row may be.
        named = f"objects[{index}]" + (f" of type {safe_finding_value(kind)!r}" if kind else "")
        why = (
            f"a second {ASSESSMENT_PROPERTY}; the one at the top level of the bundle is the "
            "one that was read"
            if kind == ASSESSMENT_PROPERTY
            else f"not a type this bundle takes from you ({', '.join(JUDGE_OBJECT_TYPES)})"
        )
        found.append(
            Violation(
                code=UNKNOWN_OBJECT_CODE,
                message=(
                    f"{named} is {why}, so it was set aside and the rest of the bundle was "
                    "read. Put what it says in an object the bundle accepts, or leave it out."
                ),
                path=f"objects[{index}]",
            )
        )
    if len(kept) != len(objects):
        bundle_dict["objects"] = kept
        logger.info(
            "judge_postprocess: %d item(s) were not STIX objects; %d object(s) were read.",
            len(objects) - len(kept),
            len(kept),
        )
    return found


DUPLICATE_LABEL_CODE = "stix.duplicate_label"


# What the judge writes on an attack-pattern or an indicator for the
# relationship the platform writes from it: its confidence, the evidence basis
# and the sources it credits.
RELATION_PROPERTIES = (
    "x_maljan_confidence",
    "x_maljan_evidence_basis",
    "x_maljan_contributing_agents",
)


def relate_to_the_sample(bundle_dict: dict[str, Any]) -> list[tuple[dict[str, Any], Any]]:
    """Write the two relationships the platform derives, where the judge wrote none.

    ``malware uses attack-pattern`` for every attack-pattern and ``indicator
    indicates malware`` for every indicator, from the bundle's one malware
    object; the judge is asked only for what it alone decides. A benchmark
    judge's bundle ran to 25,000 characters and was cut at its output cap
    twice, and a third of such a bundle is these relationships, one per
    object, each restating what its object already says. The judge's
    confidence, evidence basis and credits written on the object move onto
    the relationship unchanged. An object the judge already related that way
    gets no second relationship, and a bundle with no malware object, or with
    two, gets none: there is nothing, or no one thing, to relate to.

    Returns ``[(relationship, the object it relates)]`` in the order written.
    """
    objects = bundle_dict.get("objects")
    if not isinstance(objects, list):
        return []
    malware = [o for o in objects if isinstance(o, dict) and o.get("type") == "malware"]
    sample = malware[0].get("id") if len(malware) == 1 else None
    if not isinstance(sample, str) or not sample:
        return []
    relationships = [o for o in objects if isinstance(o, dict) and o.get("type") == "relationship"]
    used = {
        r.get("target_ref")
        for r in relationships
        if r.get("relationship_type") == "uses" and r.get("source_ref") == sample
    }
    indicating = {
        r.get("source_ref")
        for r in relationships
        if r.get("relationship_type") == "indicates" and r.get("target_ref") == sample
    }
    minted: list[tuple[dict[str, Any], Any]] = []
    for obj in list(objects):
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            continue
        kind = obj.get("type")
        if kind == "attack-pattern" and obj["id"] not in used:
            source, relation, target = sample, "uses", obj["id"]
        elif kind == "indicator" and obj["id"] not in indicating:
            source, relation, target = obj["id"], "indicates", sample
        else:
            continue
        relationship: dict[str, Any] = {
            "type": "relationship",
            "id": f"relationship--{uuid.uuid4()}",
            "relationship_type": relation,
            "source_ref": source,
            "target_ref": target,
        }
        for key in RELATION_PROPERTIES:
            if key in obj:
                relationship[key] = obj.pop(key)
        objects.append(relationship)
        minted.append((relationship, obj))
    if minted:
        logger.info(
            "judge_postprocess: related %d object(s) to the sample the judge did not relate.",
            len(minted),
        )
    return minted


def _shared_labels(objects: list[Any]) -> set[str]:
    """The ids the judge wrote on more than one object."""
    seen: set[str] = set()
    shared: set[str] = set()
    for obj in objects:
        label = obj.get("id") if isinstance(obj, dict) else None
        if isinstance(label, str):
            (shared if label in seen else seen).add(label)
    return shared


def duplicate_label_violations(
    bundle_dict: dict[str, Any], positions: Mapping[int, int] | None = None
) -> list[Violation]:
    """One question per id the judge gave to more than one object.

    Asked before any id is minted. ``positions`` maps each object (by
    ``id()``) to where the judge wrote it, so the sentence names the objects the
    judge can find in its own answer even after set-aside objects have left the
    list; without it the list's own positions are all there is.
    """
    from maljan.pipeline.events import safe_finding_value
    from maljan.pipeline.validation import Violation

    objects = bundle_dict.get("objects")
    if not isinstance(objects, list):
        return []

    def written(index: int, obj: Any) -> int:
        return positions.get(id(obj), index) if positions is not None else index

    shared = _shared_labels(objects)
    out: list[Violation] = []
    for label in sorted(shared):
        named = [
            (written(index, obj), obj)
            for index, obj in enumerate(objects)
            if isinstance(obj, dict) and obj.get("id") == label
        ]
        where = [
            f"objects[{index}] (a {safe_finding_value(_object_type(obj))})" for index, obj in named
        ]
        first = named[0][0]
        out.append(
            Violation(
                code=DUPLICATE_LABEL_CODE,
                message=(
                    f"{' and '.join(where)} share the id {safe_finding_value(label)!r}, so a "
                    "reference to it could mean either and none is read as meaning one. Give "
                    "each object its own id and name, in every reference, the one it means."
                ),
                path=f"objects[{first}]",
            )
        )
    return out


def postprocess_judge_bundle(
    bundle_dict: dict[str, Any],
    *,
    ledger: Any | None = None,
    labels: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply the defensive bundle fixes in place; return the same dict.

    ``bundle_dict`` is the parsed JSON Bundle returned by the verdict LLM,
    exactly as the judge wrote it; the technique check reports what is wrong
    with its ids, it does not filter them. ``labels``, when given, is filled
    with ``{the judge's label: the published id}`` for every label that names
    one object, and ``{label: [id, id]}`` for one two objects share, which is
    the record that lets a reader find the judge's object in the export.
    Everything done here is a shape repair — the published ids, a missing
    MITRE reference, a relationship pointing at an object that is not
    in the bundle. None of it changes what the judge decided.
    """
    objects = bundle_dict.get("objects")
    if not isinstance(objects, list):
        return bundle_dict

    # ── the published ids are minted here, every one of them ────────
    # The judge's ids only say which of its objects a reference means. A model
    # cannot generate a random UUID, so it writes one it has seen: the stored
    # exports carried one documentation-shaped malware id in fourteen runs of
    # six samples, with a version digit no RFC 4122 UUID has. A consumer
    # merging on id would fold those analyses into one object, and the OASIS
    # validator refused every object that carried or named it. The labels are
    # read once, to rewire the references, and replaced.
    #
    # A label two objects share says nothing about which one a reference
    # means, so no reference naming it is rewired onto either: each object gets
    # its own id, the references keep the label and point at nothing, and
    # ``duplicate_label_violations`` has already asked the judge which it meant.
    # Choosing the first rewired the second object's edges onto it, and the
    # integrity pass then folded them away as duplicates.
    shared = _shared_labels(objects)
    id_remap: dict[str, str] = {}
    old_ids: dict[int, str] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        old_id = obj.get("id")
        if not isinstance(old_id, str):
            continue
        old_ids[id(obj)] = old_id
        new_id = _mint_id(obj, old_id)
        if old_id not in shared:
            id_remap[old_id] = new_id
        obj["id"] = new_id
    if labels is not None:
        labels.update(id_remap)
        # A label two objects share maps to every object it names, in the
        # order written, so the record says which published ids the judge's
        # one label stood for.
        for obj in objects:
            label = old_ids.get(id(obj))
            if label in shared:
                listed = labels.setdefault(label, [])
                if isinstance(listed, list):
                    listed.append(obj["id"])
    if id_remap:
        logger.info("judge_postprocess: minted the published ids of %d object(s).", len(id_remap))
        _rewrite_references(objects, id_remap)

    # ── back-fill external_references on AttackPatterns ────────────
    _VALID_TID_RE_LOCAL = re.compile(r"^T\d{4}(?:\.\d{3})?$")
    _CURATED_PLACEHOLDERS = frozenset({"T0000", "T0000.000", "T9999", "T1234"})
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references") or []
        if refs:
            continue
        tid = _attack_pattern_technique_id(obj)
        # Never back-fill external_references
        # with a placeholder or non-MITRE-shaped value. Without this guard,
        # ``attack-pattern--<uuid>(name=T0000)`` would gain a synthesized
        # MITRE reference that links to a non-existent technique page.
        if not tid or tid in _CURATED_PLACEHOLDERS or not _VALID_TID_RE_LOCAL.match(tid):
            continue
        if tid in _MITRE_LOOKUP:
            name, url = _MITRE_LOOKUP[tid]
        else:
            # Beyond the curated table, pull the real name from the live ATT&CK
            # index when it's loaded; fall back to the LLM name / bare ID.
            name = _technique_display_name(tid) or obj.get("name") or tid
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        obj["external_references"] = [
            {"source_name": "mitre-attack", "external_id": tid, "url": url},
        ]
        # Promote a friendlier name when LLM left it as the bare ID.
        if not obj.get("name") or obj.get("name") == tid:
            obj["name"] = name

    # ── Final integrity pass: empty-pattern drop, dedup, dangling-ref sweep ──
    before = len(objects)
    # Recorded as the judge path's own: this runs once per verdict attempt,
    # discarded retries included, over objects the export may never carry, so
    # it cannot be part of the total a reader reconciles with the bundle they
    # hold.
    objects = enforce_bundle_integrity(objects, ledger=ledger, whose=JUDGE_PASS)
    bundle_dict["objects"] = objects
    if len(objects) != before:
        logger.info(
            "judge_postprocess: integrity pass kept %d/%d objects (dropped empty/dup/dangling).",
            len(objects),
            before,
        )

    return bundle_dict


# ---------------------------------------------------------------------------
# Indicator admission
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mint_id(obj: dict[str, Any], old_id: str) -> str:
    """Generate a spec-compliant STIX ID for ``obj``, under its own type.

    For ``attack-pattern--T1497`` we hash the technique ID into a stable
    UUID5 so identical techniques map to identical IDs across runs.
    Anything else gets a fresh random UUID4.
    """
    stix_type = obj.get("type") or _parse_type(old_id) or "indicator"
    if stix_type == "attack-pattern":
        suffix = _parse_type_suffix(old_id) or ""
        tid = _attack_pattern_technique_id(obj) or (
            suffix if re.match(r"^T\d{4}(?:\.\d{3})?$", suffix) else None
        )
        if tid:
            from maljan.schemas.stix_models import attack_pattern_id

            return attack_pattern_id(tid)
    return f"{stix_type}--{uuid.uuid4()}"


def _parse_type(stix_id: str) -> str | None:
    if "--" in stix_id:
        return stix_id.split("--", 1)[0]
    return None


def _parse_type_suffix(stix_id: str) -> str | None:
    if "--" in stix_id:
        return stix_id.split("--", 1)[1]
    return None


def _attack_pattern_technique_id(obj: dict[str, Any]) -> str | None:
    r"""Best-effort technique ID extraction from an ``attack-pattern`` SDO.

    Order of attempts:
    1. ``external_references[*].external_id`` matching ``T####``.
    2. ``name`` matching ``^T####(\.###)?$``.
    3. ``x_maljan_technique_id`` (Maljan custom field).
    """
    declared = attack_reference_id(obj)
    if re.match(r"^T\d{4}(?:\.\d{3})?$", declared):
        return declared
    name = obj.get("name", "")
    if isinstance(name, str) and re.match(r"^T\d{4}(?:\.\d{3})?$", name.strip()):
        return name.strip()
    custom = obj.get("x_maljan_technique_id")
    if isinstance(custom, str) and re.match(r"^T\d{4}(?:\.\d{3})?$", custom.strip()):
        return custom.strip()
    return None


def _rewrite_references(objects: list[Any], id_remap: dict[str, str]) -> None:
    """In-place: rewrite every ``*_ref`` and ``*_refs`` property through ``id_remap``.

    Every one, because an observable names others by more than the three an
    SDO does — a process's ``image_ref``, ``parent_ref`` and ``child_refs``, a
    file's ``parent_directory_ref`` — and a reference left on the judge's label
    would name nothing in the published bundle.
    """
    if not id_remap:
        return
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        for key, value in list(obj.items()):
            if key.endswith("_ref") and isinstance(value, str) and value in id_remap:
                obj[key] = id_remap[value]
            elif key.endswith("_refs") and isinstance(value, list):
                obj[key] = [id_remap.get(r, r) if isinstance(r, str) else r for r in value]


def _oid(o: Any) -> Any:
    return o.get("id") if isinstance(o, dict) else getattr(o, "id", None)


def _otype(o: Any) -> Any:
    return o.get("type") if isinstance(o, dict) else getattr(o, "type", None)


def _oget(o: Any, key: str, default: Any = None) -> Any:
    return o.get(key, default) if isinstance(o, dict) else getattr(o, key, default)


def _oset(o: Any, key: str, value: Any) -> None:
    if isinstance(o, dict):
        o[key] = value
    else:
        setattr(o, key, value)


def _technique_id_poly(o: Any) -> str | None:
    """Technique ID from an attack-pattern (dict or pydantic), via refs or name."""
    declared = attack_reference_id(o)
    if re.match(r"^T\d{4}(?:\.\d{3})?$", declared):
        return declared
    name = _oget(o, "name", "") or ""
    if isinstance(name, str) and re.match(r"^T\d{4}(?:\.\d{3})?$", name.strip()):
        return name.strip()
    return None


def _remap_refs_poly(objects: list[Any], remap: dict[str, str]) -> None:
    """Rewrite source_ref/target_ref/object_refs through ``remap`` (dict or pydantic)."""
    if not remap:
        return
    for o in objects:
        for key in ("source_ref", "target_ref"):
            v = _oget(o, key)
            if isinstance(v, str) and v in remap:
                _oset(o, key, remap[v])
        refs = _oget(o, "object_refs")
        if isinstance(refs, list):
            _oset(o, "object_refs", [remap.get(r, r) for r in refs])


def _is_wellformed_pattern(indicator: Any) -> bool:
    """Conservative STIX 2.1 pattern shape check for an indicator object.

    Returns True only when the pattern is a bracketed comparison expression
    (``[ <path> <op> '<value>' ]``). Keeps all patterns Maljan emits; rejects
    empty/whitespace and truncated/garbage LLM output — a ``[file:name``
    comparison cut off before its closing bracket, say.
    """
    pat = str(_oget(indicator, "pattern", "") or "").strip()
    return pat.startswith("[") and pat.endswith("]") and "=" in pat


def _merge_indicator_sets(kept: Any, duplicate: Any) -> None:
    """Fold the set-shaped fields of a duplicate indicator onto the kept one.

    Only the sets: ``labels`` and ``external_references`` are lists of things
    an indicator is filed under, and losing one because two analysts described
    the same endpoint is losing a fact. Everything else — the description, the
    confidence, the valid-from — stays as the first occurrence wrote it, and
    an SDO that will not take a new value (a frozen pydantic object) is left
    alone rather than rebuilt.
    """
    for field in ("labels", "external_references"):
        arriving = _oget(duplicate, field)
        if not isinstance(arriving, list) or not arriving:
            continue
        current = list(_oget(kept, field) or [])
        merged = list(current)
        for item in arriving:
            if item not in merged:
                merged.append(item)
        if merged == current:
            continue
        try:
            _oset(kept, field, merged)
        except Exception as exc:  # noqa: BLE001 — a frozen SDO keeps what it has
            logger.debug("indicator merge skipped for %r (%s).", field, exc)


def enforce_bundle_integrity(
    objects: list[Any],
    *,
    ledger: Any | None = None,
    dropped_as: str | None = None,
    whose: str = EXPORT_PASS,
) -> list[Any]:
    """Make a STIX object list internally valid and non-redundant, in place-ish.

    Works on both parsed dicts (judge bundle) and pydantic SDOs (extended
    bundle). Order-preserving. Steps:
      1. Drop indicators with an empty/whitespace pattern (STIX 2.1 invalid).
      2. Deduplicate attack-patterns by technique ID (keep first; remap refs).
      3. Deduplicate indicators by (pattern_type, pattern) (keep first; remap refs).
      4. Drop relationships whose source/target is not in the bundle, and
         deduplicate identical relationships.
      5. Trim object_refs (Report/Note) to objects that still exist.

    Args:
        objects: The bundle contents to repair.
        ledger:  Optional :class:`~maljan.core.truncation_ledger.TruncationLedger`.
                 The claim that repairing beats rejecting needs a number for how
                 often this pass fires and what it removes, and nothing counted it
                 before. Typed loosely to keep this module free of a core import
                 it does not otherwise need.
        whose: Which bundle this pass ran on. The export's passes are the ones
                 the run summary reconciles with the published bundle; the
                 judge path's run per verdict attempt and are counted apart.
        dropped_as: One reason to file everything this run of the pass removes
                 under, in place of the per-step reasons. The caller that sweeps
                 up after the indicator cap uses it: nothing there is a defect of
                 anybody's bundle, it is all the cap's own loss, and one name for
                 it keeps that separate from what the first pass repaired.
    """
    _objects_in = len(objects)
    _dropped: dict[str, int] = {}

    # 1) drop indicators with an empty or syntactically malformed pattern. The
    # shape check is deliberately conservative — a STIX comparison expression is
    # wrapped in brackets and contains a comparator — so it keeps every pattern
    # this codebase emits and only rejects truncated/garbage LLM output (no full
    # grammar parser, hence no over-dropping).
    _before = len(objects)
    objects = [o for o in objects if _otype(o) != "indicator" or _is_wellformed_pattern(o)]
    _dropped["empty_pattern"] = _before - len(objects)

    remap: dict[str, str] = {}

    # 2) attack-pattern dedup by technique ID
    seen_tid: dict[str, str] = {}
    kept: list[Any] = []
    for o in objects:
        if _otype(o) == "attack-pattern":
            tid = _technique_id_poly(o)
            if tid and tid in seen_tid:
                oid = _oid(o)
                if isinstance(oid, str):
                    remap[oid] = seen_tid[tid]
                continue
            if tid and isinstance(_oid(o), str):
                seen_tid[tid] = _oid(o)
        kept.append(o)
    _dropped["duplicate_attack_pattern"] = len(objects) - len(kept)
    objects = kept

    # 3) indicator dedup by (pattern type, canonical pattern). Canonical
    # because two indicators for one endpoint differ by whether whoever wrote
    # them defanged it, and an exact comparison kept both; canonical *with the
    # case kept* wherever the case is part of the value, because a URL path is
    # case-sensitive and folding one away removes a fact from the report.
    # ``reporting.dedupe`` is the one place that says what makes two
    # indicators the same, so the bundle and the report's table agree.
    seen_pat: dict[tuple[str, str], Any] = {}
    kept = []
    for o in objects:
        if _otype(o) == "indicator":
            key = pattern_fingerprint(_oget(o, "pattern_type", "stix"), _oget(o, "pattern", ""))
            first = seen_pat.get(key)
            if first is not None:
                _merge_indicator_sets(first, o)
                oid = _oid(o)
                if isinstance(oid, str):
                    remap[oid] = _oid(first)
                continue
            if isinstance(_oid(o), str):
                seen_pat[key] = o
        kept.append(o)
    _dropped["duplicate_indicator"] = len(objects) - len(kept)
    objects = kept

    # apply remap so refs to deduped objects point at the kept ones
    _remap_refs_poly(objects, remap)

    # 4) drop dangling + duplicate relationships
    ids = {_oid(o) for o in objects}
    seen_rel: set[tuple[str, str, str]] = set()
    _dangling = 0
    _dup_rel = 0
    kept = []
    for o in objects:
        if _otype(o) == "relationship":
            src, tgt = _oget(o, "source_ref"), _oget(o, "target_ref")
            if src not in ids or tgt not in ids:
                _dangling += 1
                continue
            rkey = (str(_oget(o, "relationship_type", "")), str(src), str(tgt))
            if rkey in seen_rel:
                _dup_rel += 1
                continue
            seen_rel.add(rkey)
        kept.append(o)
    _dropped["dangling_relationship"] = _dangling
    _dropped["duplicate_relationship"] = _dup_rel
    objects = kept

    # 5) trim object_refs to surviving objects. What this takes out removes no
    # object, so it is not one of the reasons — but it is a removal, and a
    # reader comparing the exported bundle with the judge's own would find it
    # nowhere if it were not counted.
    ids = {_oid(o) for o in objects}
    _refs_trimmed = 0
    for o in objects:
        for ref_key in ("object_refs", "sample_refs"):
            refs = _oget(o, ref_key)
            if isinstance(refs, list):
                surviving = [r for r in refs if r in ids]
                _refs_trimmed += len(refs) - len(surviving)
                _oset(o, ref_key, surviving)

    if ledger is not None:
        try:
            ledger.record_integrity_pass(
                objects_in=_objects_in,
                objects_out=len(objects),
                dropped=(
                    {dropped_as: sum(_dropped.values())} if dropped_as is not None else _dropped
                ),
                refs_trimmed=_refs_trimmed,
                whose=whose,
            )
        except Exception:  # noqa: BLE001 — telemetry must never break a bundle
            pass

    return objects


def build_evidence_corpus(
    *,
    interesting_strings: list[dict[str, Any]] | None = None,
    sandbox_report: dict[str, Any] | None = None,
    extra: list[str] | None = None,
) -> set[str]:
    """Build the lower-cased token set used by the indicator filter.

    The output deliberately overcollects (whole strings, parts split on
    ``/`` or ``.``) so a substring check inside :func:`postprocess_judge_bundle`
    is cheap. ``False positives'' here are fine — they only allow a
    questionable indicator through, which is preferable to dropping a
    valid one.
    """
    corpus: set[str] = set()

    for item in interesting_strings or []:
        v = item.get("value") if isinstance(item, dict) else None
        if isinstance(v, str) and v:
            corpus.add(v.lower())

    if isinstance(sandbox_report, dict):
        network = sandbox_report.get("network") or {}
        for kind in ("dns", "http", "tcp", "udp"):
            for entry in network.get(kind) or []:
                if isinstance(entry, str):
                    corpus.add(entry.lower())
                elif isinstance(entry, dict):
                    for v in entry.values():
                        if isinstance(v, str) and v:
                            corpus.add(v.lower())

    for s in extra or []:
        if isinstance(s, str) and s:
            corpus.add(s.lower())

    return corpus
