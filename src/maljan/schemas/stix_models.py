"""STIX 2.1 Domain Object schemas with per-claim confidence intervals.

Adds ``ConfidenceAnnotatedRelationship``.

Literature gap: No existing system adds per-claim uncertainty scores and
multi-agent attribution metadata to STIX 2.1 Relationship objects. Standard
STIX 2.1 defines a top-level 'confidence' property (0-100 integer) on SDOs
but it is rarely populated and carries no evidence provenance.

Maljan extends Relationship with three novel fields:
  - confidence:            Float 0.0-1.0, the judge's own confidence in this
                           relationship. Nothing recomputes it downstream.
  - evidence_basis:        Which data domain(s) support this relationship
                           (e.g. "static+dynamic", "network", "all").
  - contributing_agents:   Which analysis agents observed supporting evidence.

These fields are STIX custom properties (prefixed with 'x_maljan_') to comply
with the STIX 2.1 custom property specification and avoid namespace collisions.

EvidenceBasis: controlled vocabulary of evidence provenance categories.
  - "static"              PE/ELF binary + decompiled code evidence
  - "dynamic"             Sandbox behavior trace evidence
  - "network"             Network capture evidence
  - "static+dynamic"      Two of the three corroborate it
  - "dynamic+network"     Two of the three corroborate it
  - "static+network"      Two of the three corroborate it
  - "all"                 All three corroborate it

Usage in judge prompt: the judge is instructed to populate these fields per
relationship object, and is shown the evidence summary
(``pipeline.evidence_summary``) — every source that named each technique and
what each of them said its own confidence was. It sets the number; nothing
computes one for it, and nothing adjusts the one it sets.

Backward compatibility: All new fields are Optional with safe defaults so
existing code producing plain Relationship objects still works. The Bundle
union type is updated to include ConfidenceAnnotatedRelationship.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from maljan.schemas.judgement import JudgeAssessment


def _generate_uuid() -> str:
    """Generate a standard UUID string for STIX objects."""
    return str(uuid.uuid4())


def get_utcnow() -> datetime:
    """Helper to return aware UTC datetime for STIX timestamp defaults."""
    return datetime.now(UTC)


# The namespace a technique's object id is derived in. A UUIDv5 over the
# technique id, so one technique is one object across exports and across runs,
# whichever bundle carries it — the judge's own or the export — and never a
# UUID copied out of the STIX documentation.
ATTACK_PATTERN_NAMESPACE = uuid.UUID("2f0b4c10-6f7e-5b6a-9d3b-1f6a5c7e8d90")


def attack_pattern_id(technique_id: str) -> str:
    """The object id of one ATT&CK technique. The same id every time."""
    return f"attack-pattern--{uuid.uuid5(ATTACK_PATTERN_NAMESPACE, technique_id)}"


# ---------------------------------------------------------------------------
# Evidence basis controlled vocabulary
# ---------------------------------------------------------------------------

EvidenceBasis = Literal[
    "static",
    "dynamic",
    "network",
    "static+dynamic",
    "dynamic+network",
    "static+network",
    "all",
    "unknown",
]


# ---------------------------------------------------------------------------
# STIX Domain Objects (unchanged from original)
# ---------------------------------------------------------------------------


class _SpecConformantModel(BaseModel):
    """Serialises the way STIX 2.1 requires, rather than the way pydantic defaults to.

    Two spec rules pydantic will happily break for you, both found on 2026-08-08 when
    the OASIS ``cti-stix-validator`` was pointed at our output for the first time:

    * **null properties are not allowed in STIX** — an absent optional property must be
      omitted, not serialised as ``null``. Pydantic emits ``"description": null``.
    * **empty arrays are not allowed** — a list-valued property that is present must be
      non-empty. Our ``malware_types`` and ``indicator_types`` default to ``[]``.

    Overriding the dump methods rather than fixing call sites is deliberate: the bundle
    is serialised in several places (renderer, API, long-term memory) and a rule that
    holds only where somebody remembered to pass a flag is not a rule.
    """

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("exclude_none", True)
        cleaned = _drop_empty_sequences(super().model_dump(**kwargs))
        assert isinstance(cleaned, dict)  # noqa: S101 - a model always dumps to a mapping
        return cleaned

    def model_dump_json(self, **kwargs: Any) -> str:
        import json as _json

        kwargs.setdefault("exclude_none", True)
        kwargs.pop("mode", None)
        return _json.dumps(self.model_dump(mode="json", **kwargs))


def _drop_empty_sequences(value: Any) -> Any:
    """Recursively remove empty lists/dicts, which STIX forbids as present properties.

    Applied to the dumped structure rather than to the model, so a field that is
    *meaningfully* empty in Python still round-trips through the object graph and only
    disappears at the wire format — which is the only place the spec has an opinion.
    """
    if isinstance(value, dict):
        return {
            k: _drop_empty_sequences(v)
            for k, v in value.items()
            if not (isinstance(v, list | dict) and not v)
        }
    if isinstance(value, list):
        return [_drop_empty_sequences(v) for v in value]
    return value


class STIXObject(_SpecConformantModel):
    """Base generic properties for all STIX Domain Objects (SDOs).

    ``spec_version`` is **required** on every SDO in STIX 2.1 — it moved from the
    bundle (where 2.0 put it) onto the objects themselves. We emitted it nowhere, so
    every bundle this project ever produced was, strictly, not identifiable as 2.1:
    a consumer applying the spec falls back to 2.0 semantics, and the OASIS
    ``cti-stix-validator`` refuses the object outright.

    Found by running that validator over four bundles from real runs, while
    measuring something else entirely. Our own integrity pass has opinions about
    empty patterns, duplicate attack-patterns and dangling references, and no
    opinion at all about this — which
    is the argument for grading output with someone else's instrument, demonstrated
    on ourselves.
    """

    type: str
    id: str
    spec_version: Literal["2.1"] = "2.1"
    created: datetime = Field(default_factory=get_utcnow)
    modified: datetime = Field(default_factory=get_utcnow)
    # The identity that produced the object. The export names this platform's
    # own identity on every object it publishes; ``None`` keeps the property
    # out of a bundle that has no identity to name.
    created_by_ref: str | None = None


class Indicator(STIXObject):
    """STIX 2.1 Indicator representing a pattern that denotes malicious behavior."""

    type: Literal["indicator"] = "indicator"
    id: str = Field(default_factory=lambda: f"indicator--{_generate_uuid()}")
    name: str | None = None
    description: str | None = None
    # Empty, and so absent from the dump, when nobody wrote one: STIX 2.1 makes
    # the property optional, and the ``malicious-activity`` this defaulted to
    # was published as the judge's word on an indicator it had left untyped.
    indicator_types: list[str] = Field(default_factory=list)
    pattern: str
    pattern_type: str = "stix"
    valid_from: datetime = Field(default_factory=get_utcnow)


class Malware(STIXObject):
    """STIX 2.1 Malware representation.

    The three ``x_maljan_`` properties are declared rather than passed through.
    Pydantic ignores keys a model does not declare, so the judge's fallback
    builder had been setting ``x_maljan_fallback_reasoning`` on this object for
    debug consumers, its own comment said so, and the property reached no
    consumer at all: it was dropped at validation, before any dump. That is the
    same shape as the renamed output ceiling of Section 3.8 -- a guarantee
    stated where nothing reads it -- so the fields are on the model now, where
    the serialiser can see them.

    ``None`` keeps them out of the bundle entirely, which is what STIX requires
    of an absent property.
    """

    type: Literal["malware"] = "malware"
    id: str = Field(default_factory=lambda: f"malware--{_generate_uuid()}")
    name: str
    description: str | None = None
    # ``None`` when the judge did not say. STIX requires the property, so the
    # judge is asked for it (``stix.is_family_missing``); the ``False`` this
    # defaulted to was a statement nobody made.
    is_family: bool | None = None
    malware_types: list[str] = Field(default_factory=list)
    x_maljan_fallback_reasoning: str | None = None
    x_maljan_degraded_path: bool | None = None
    x_maljan_model_only_technique_ids: list[str] | None = None


class Relationship(STIXObject):
    """STIX 2.1 Relationship structure to connect SDOs (plain, no annotation)."""

    type: Literal["relationship"] = "relationship"
    id: str = Field(default_factory=lambda: f"relationship--{_generate_uuid()}")
    relationship_type: str
    source_ref: str
    target_ref: str


class ConfidenceAnnotatedRelationship(STIXObject):
    """STIX 2.1 Relationship with per-claim confidence interval and provenance.

    This extends the plain Relationship with three custom properties that
    represent a novel contribution: evidence-grounded uncertainty quantification
    in STIX intelligence bundles.

    Attributes:
        relationship_type:      Standard STIX relationship type verb
                                (e.g., "uses", "indicates", "attributed-to").
        source_ref:             STIX ID of the source object.
        target_ref:             STIX ID of the target object.
        x_maljan_confidence:    The judge's confidence [0.0, 1.0] in this
                                relationship claim, set from the evidence
                                summary it was shown. Carried through to the
                                capability matrix unchanged.
        x_maljan_evidence_basis: Which analysis domain(s) produced supporting
                                evidence. Uses EvidenceBasis controlled vocab.
        x_maljan_contributing_agents: List of agent IDs that observed evidence
                                supporting this relationship. Empty = LLM-inferred.
        x_maljan_technique_id:  MITRE ATT&CK technique ID if applicable.
    """

    type: Literal["relationship"] = "relationship"
    id: str = Field(default_factory=lambda: f"relationship--{_generate_uuid()}")
    relationship_type: str
    source_ref: str
    target_ref: str

    # Custom extension fields (STIX 2.1 custom property convention: x_ prefix).
    # ``None`` where nobody wrote one, which keeps the property out of the
    # bundle. They defaulted to 0.5 and ``unknown``, so a relationship the
    # judge wrote without a number — and the relationships the text fallback
    # builds — were published carrying a confidence nobody had stated.
    #
    # Typed loosely on purpose. They were typed strictly (a number in 0–1, a
    # basis from the list), and a relationship failing that type parsed as a
    # plain ``Relationship`` instead — the whole annotation gone, nothing
    # recorded. A value outside the schema is the judge's answer and is kept as
    # written; ``pipeline.validation.annotation_out_of_schema_violations`` asks
    # about it, and a reader takes a number only when it is one in 0–1
    # (:func:`stated_confidence`).
    x_maljan_confidence: float | str | None = None
    x_maljan_evidence_basis: str | None = None
    x_maljan_contributing_agents: list[str] | str = Field(default_factory=list)
    x_maljan_technique_id: str | None = None

    @property
    def is_high_confidence(self) -> bool:
        """True if confidence >= 0.80 (two-sigma threshold); a missing one is not."""
        stated = stated_confidence(self.x_maljan_confidence)
        return stated is not None and stated >= 0.80

    @property
    def is_multi_domain(self) -> bool:
        """True if evidence spans more than one analysis domain."""
        basis = self.x_maljan_evidence_basis or ""
        return "+" in basis or basis == "all"

    def confidence_label(self) -> str:
        """Human-readable confidence tier label."""
        stated = stated_confidence(self.x_maljan_confidence)
        if stated is None:
            return "NOT ASSESSED"
        if stated >= 0.90:
            return "HIGH"
        if stated >= 0.70:
            return "MEDIUM"
        if stated >= 0.50:
            return "LOW"
        return "SPECULATIVE"


def produced_by(obj: STIXObject, producer: str) -> STIXObject:
    """A copy of ``obj`` naming ``producer`` as the identity that produced it.

    A copy, so the bundle the object came from keeps what it said. The export
    calls it for every object it publishes; which producer an object already
    names, and whether that one is kept, is the renderer's decision.
    """
    return obj.model_copy(update={"created_by_ref": producer})


def crediting_only(obj: Any, agents: list[str]) -> Any:
    """A copy of a relationship crediting ``agents`` and no one else.

    A copy, so the judge's own bundle keeps every name it wrote. The export
    calls it for a credit the judge was asked about and kept, naming an agent
    no source of that name stands behind, and records that it did.
    """
    return obj.model_copy(update={"x_maljan_contributing_agents": agents})


def stated_confidence(value: Any) -> float | None:
    """A confidence as a number in 0–1, or ``None`` when it is not one.

    ``None`` for an absent value and for one outside the scale: ``95`` or
    ``"high"`` is a statement the judge is asked about, not a number any reader
    may put on a technique.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if 0.0 <= number <= 1.0 else None


class AttackPattern(STIXObject):
    """STIX 2.1 Attack Pattern, used to represent MITRE ATT&CK TTPs."""

    type: Literal["attack-pattern"] = "attack-pattern"
    id: str = Field(default_factory=lambda: f"attack-pattern--{_generate_uuid()}")
    name: str
    description: str | None = None
    external_references: list[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Extended SDOs — populated by the report node's ExtendedSTIXRenderer.
# ---------------------------------------------------------------------------


class Identity(STIXObject):
    """STIX 2.1 Identity — used to mark Maljan itself as the report producer."""

    type: Literal["identity"] = "identity"
    id: str = Field(default_factory=lambda: f"identity--{_generate_uuid()}")
    name: str
    identity_class: str = "software"
    description: str | None = None


class ObservedData(STIXObject):
    """STIX 2.1 Observed Data — a snapshot of sandbox observations.

    The observables are objects of the bundle, named by ``object_refs``. The
    2.0 form — an ``objects`` dictionary of embedded observables — is
    deprecated in 2.1, and the one this used to carry held ``process`` entries
    with no id and a ``name`` 2.1 does not define, which the OASIS validator
    could not read at all. ``number_observed`` is how many times the snapshot
    was seen: one sandbox run is one.
    """

    type: Literal["observed-data"] = "observed-data"
    id: str = Field(default_factory=lambda: f"observed-data--{_generate_uuid()}")
    first_observed: datetime = Field(default_factory=get_utcnow)
    last_observed: datetime = Field(default_factory=get_utcnow)
    number_observed: int = 1
    object_refs: list[str] = Field(default_factory=list)


# The namespace STIX 2.1 derives Cyber-observable ids in (section 2.9).
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class _Observable(_SpecConformantModel):
    """A STIX 2.1 Cyber-observable: an id and a type, no SDO bookkeeping."""

    type: str
    id: str
    spec_version: Literal["2.1"] = "2.1"


class File(_Observable):
    """STIX 2.1 ``file`` observable, here the image a process ran from.

    Its id is derived from its name, as the standard derives a file's id from
    its identifying properties, so one image is one object in every export.
    """

    type: Literal["file"] = "file"
    id: str = ""
    name: str

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            key = json_canonical({"name": self.name})
            self.id = f"file--{uuid.uuid5(SCO_NAMESPACE, key)}"


class Process(_Observable):
    """STIX 2.1 ``process`` observable: a pid, its command line, its image and children."""

    type: Literal["process"] = "process"
    id: str = Field(default_factory=lambda: f"process--{_generate_uuid()}")
    pid: int | None = None
    command_line: str | None = None
    image_ref: str | None = None
    child_refs: list[str] = Field(default_factory=list)


def json_canonical(value: Any) -> str:
    """The canonical JSON a derived observable id is computed over."""
    import json as _json

    return _json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Note(STIXObject):
    """STIX 2.1 Note — wraps the LLM-generated executive summary.

    It also carries the fallback record of a bundle with no ``malware`` object.
    The two ``x_maljan_`` properties are the same ones :class:`Malware` carries
    and they say the same things: that this bundle came off the degraded path,
    and which technique ids appeared in the model's raw text and in no evidence
    claim, recorded and not emitted. A verdict that is not Malware has no
    malware object to hang them on, and dropping them there would have made the
    record depend on the verdict.
    """

    type: Literal["note"] = "note"
    id: str = Field(default_factory=lambda: f"note--{_generate_uuid()}")
    abstract: str | None = None
    content: str
    object_refs: list[str] = Field(default_factory=list)
    x_maljan_degraded_path: bool | None = None
    x_maljan_model_only_technique_ids: list[str] | None = None


class Report(STIXObject):
    """STIX 2.1 Report — the top-level container linking every SDO in this analysis."""

    type: Literal["report"] = "report"
    id: str = Field(default_factory=lambda: f"report--{_generate_uuid()}")
    name: str
    description: str | None = None
    report_types: list[str] = Field(default_factory=lambda: ["malware"])
    published: datetime = Field(default_factory=get_utcnow)
    object_refs: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Bundle — updated to include ConfidenceAnnotatedRelationship + extended SDOs
# ---------------------------------------------------------------------------

# Discriminated union: Pydantic resolves ambiguity between Relationship and
# ConfidenceAnnotatedRelationship via the presence of x_maljan_confidence.
# Extended SDOs (Identity/ObservedData/Note/Report) are appended — judge's
# minimal bundle continues to validate because every member is still
# left-to-right resolvable by the union.
_BundleObject = (
    Indicator
    | Malware
    | ConfidenceAnnotatedRelationship
    | Relationship
    | AttackPattern
    | Identity
    | ObservedData
    | Note
    | Report
    | Process
    | File
)


class FallbackVerdict(_SpecConformantModel):
    """The verdict a bundle carries when the judge did not express one.

    ``source`` is the whole point. ``extracted`` means the judge answered with
    text and this decision was read out of that text, so it is still the
    model's word. ``pipeline`` means there was no answer to read — a timeout —
    and the decision is this pipeline's own conservative one. Either way the
    bundle's object set follows the decision rather than deciding it, which is
    how a judge that never answered came to produce "Malware".
    """

    decision: str
    source: Literal["extracted", "pipeline"]


class Bundle(_SpecConformantModel):
    """STIX 2.1 Bundle container for transferring multiple objects.

    The objects list accepts both plain Relationship and
    ConfidenceAnnotatedRelationship. Pydantic resolves the union left-to-right
    so ConfidenceAnnotatedRelationship (with extra fields) is tried first.
    """

    type: Literal["bundle"] = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{_generate_uuid()}")
    objects: list[_BundleObject] = Field(default_factory=list)
    # Severity, malware category and family attribution, as the judge answered
    # them. A STIX custom property (``x_`` prefixed, per the spec's extension
    # rule) rather than three bare bundle fields, because the Bundle's property
    # set is defined by STIX 2.1 and a validator reads it strictly. ``None``
    # when the judge did not produce one, which the report prints as such.
    x_maljan_assessment: JudgeAssessment | None = None
    # Set only on a bundle this pipeline built because the judge's answer was
    # not a bundle. ``None`` on every bundle a judge actually produced, and a
    # reader that wants the verdict asks ``pipeline.outcome.decide_from_bundle``
    # rather than counting objects.
    x_maljan_fallback_verdict: FallbackVerdict | None = None

    def confidence_annotated_relationships(self) -> list[ConfidenceAnnotatedRelationship]:
        """Return only the ConfidenceAnnotatedRelationship objects in this bundle."""
        return [obj for obj in self.objects if isinstance(obj, ConfidenceAnnotatedRelationship)]

    def mean_relationship_confidence(self) -> float | None:
        """Compute mean confidence across all annotated relationships.

        Returns None if no relationship states a confidence.
        """
        stated = [
            number
            for r in self.confidence_annotated_relationships()
            if (number := stated_confidence(r.x_maljan_confidence)) is not None
        ]
        if not stated:
            return None
        return sum(stated) / len(stated)


def _bundle_object_types() -> frozenset[str]:
    """Every ``type`` the union above accepts, read off the union itself.

    Read rather than listed, so a member added to ``_BundleObject`` is known
    here without anybody remembering to say so twice. The caller is the pass
    that sets aside an object the Bundle cannot hold, and a stale list there
    would throw away an object the schema would have taken.
    """
    import typing

    found: set[str] = set()
    for member in typing.get_args(_BundleObject):
        field = member.model_fields.get("type")
        if field is None:
            continue
        found.update(str(value) for value in typing.get_args(field.annotation))
    return frozenset(found)


# The STIX types a ``Bundle`` can hold. Anything else inside ``objects`` fails
# the whole bundle, which is why one misplaced extension object used to cost a
# judge's twenty-five-object answer.
BUNDLE_OBJECT_TYPES: frozenset[str] = _bundle_object_types()

# The bundle's own extension property, and the only ``type`` value the lift
# pass recognises as something that belongs beside ``objects`` rather than in
# it. The judge is asked for it at the top level and writes it inside the list
# often enough to have cost two live runs their bundles.
ASSESSMENT_PROPERTY = "x_maljan_assessment"
