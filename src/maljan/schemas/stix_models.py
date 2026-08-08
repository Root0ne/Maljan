"""STIX 2.1 Domain Object schemas with per-claim confidence intervals.

Phase 7.2 addition: ConfidenceAnnotatedRelationship

Literature gap: No existing system adds per-claim uncertainty scores and
multi-agent attribution metadata to STIX 2.1 Relationship objects. Standard
STIX 2.1 defines a top-level 'confidence' property (0-100 integer) on SDOs
but it is rarely populated and carries no evidence provenance.

Maljan extends Relationship with three novel fields:
  - confidence:            Weighted float 0.0-1.0 (from TTP cascade scoring
                           or agent mean_confidence when cascade unavailable).
  - evidence_basis:        Which data domain(s) support this relationship
                           (e.g. "static+dynamic", "network", "all").
  - contributing_agents:   Which analysis agents observed supporting evidence.

These fields are STIX custom properties (prefixed with 'x_maljan_') to comply
with the STIX 2.1 custom property specification and avoid namespace collisions.

EvidenceBasis: controlled vocabulary of evidence provenance categories.
  - "static"              PE/ELF binary + decompiled code evidence
  - "dynamic"             Sandbox behavior trace evidence
  - "network"             Network capture evidence
  - "static+dynamic"      Corroborated by two layers
  - "dynamic+network"     Corroborated by two layers
  - "static+network"      Corroborated by two layers
  - "all"                 Consensus across all three layers

Usage in judge prompt: The LLM is instructed to populate these fields per
relationship object. When cascade_summary is available, the judge is given
pre-computed confidence scores and contributing layers for each TTP, reducing
LLM uncertainty and hallucination.

Backward compatibility: All new fields are Optional with safe defaults so
existing code producing plain Relationship objects still works. The Bundle
union type is updated to include ConfidenceAnnotatedRelationship.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field


def _generate_uuid() -> str:
    """Generate a standard UUID string for STIX objects."""
    return str(uuid.uuid4())


def get_utcnow() -> datetime:
    """Helper to return aware UTC datetime for STIX timestamp defaults."""
    return datetime.now(UTC)


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

    Found on 2026-08-08 by running that validator over four bundles from real runs,
    while measuring something else entirely (`tests/evaluation/eval_stix_integrity.py`).
    Our own integrity pass has opinions about empty patterns, duplicate
    attack-patterns and dangling references, and no opinion at all about this — which
    is the argument for grading output with someone else's instrument, demonstrated
    on ourselves.
    """

    type: str
    id: str
    spec_version: Literal["2.1"] = "2.1"
    created: datetime = Field(default_factory=get_utcnow)
    modified: datetime = Field(default_factory=get_utcnow)


class Indicator(STIXObject):
    """STIX 2.1 Indicator representing a pattern that denotes malicious behavior."""

    type: Literal["indicator"] = "indicator"
    id: str = Field(default_factory=lambda: f"indicator--{_generate_uuid()}")
    name: str | None = None
    description: str | None = None
    indicator_types: list[str] = Field(default_factory=lambda: ["malicious-activity"])
    pattern: str
    pattern_type: str = "stix"
    valid_from: datetime = Field(default_factory=get_utcnow)


class Malware(STIXObject):
    """STIX 2.1 Malware representation."""

    type: Literal["malware"] = "malware"
    id: str = Field(default_factory=lambda: f"malware--{_generate_uuid()}")
    name: str
    description: str | None = None
    is_family: bool = False
    malware_types: list[str] = Field(default_factory=list)


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
        x_maljan_confidence:    Weighted confidence score [0.0, 1.0] for this
                                relationship claim. Derived from TTP cascade
                                weighted confidence or agent mean_confidence.
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

    # Custom extension fields (STIX 2.1 custom property convention: x_ prefix)
    x_maljan_confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    x_maljan_evidence_basis: EvidenceBasis = "unknown"
    x_maljan_contributing_agents: list[str] = Field(default_factory=list)
    x_maljan_technique_id: str | None = None

    @property
    def is_high_confidence(self) -> bool:
        """True if confidence >= 0.80 (two-sigma threshold)."""
        return self.x_maljan_confidence >= 0.80

    @property
    def is_multi_domain(self) -> bool:
        """True if evidence spans more than one analysis domain."""
        return "+" in self.x_maljan_evidence_basis or self.x_maljan_evidence_basis == "all"

    def confidence_label(self) -> str:
        """Human-readable confidence tier label."""
        if self.x_maljan_confidence >= 0.90:
            return "HIGH"
        if self.x_maljan_confidence >= 0.70:
            return "MEDIUM"
        if self.x_maljan_confidence >= 0.50:
            return "LOW"
        return "SPECULATIVE"


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
    """STIX 2.1 Observed Data — a snapshot of sandbox observations."""

    type: Literal["observed-data"] = "observed-data"
    id: str = Field(default_factory=lambda: f"observed-data--{_generate_uuid()}")
    first_observed: datetime = Field(default_factory=get_utcnow)
    last_observed: datetime = Field(default_factory=get_utcnow)
    number_observed: int = 1
    objects: dict[str, Any] = Field(default_factory=dict)


class Note(STIXObject):
    """STIX 2.1 Note — wraps the LLM-generated executive summary."""

    type: Literal["note"] = "note"
    id: str = Field(default_factory=lambda: f"note--{_generate_uuid()}")
    abstract: str | None = None
    content: str
    object_refs: list[str] = Field(default_factory=list)


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
)


class Bundle(_SpecConformantModel):
    """STIX 2.1 Bundle container for transferring multiple objects.

    The objects list accepts both plain Relationship and
    ConfidenceAnnotatedRelationship. Pydantic resolves the union left-to-right
    so ConfidenceAnnotatedRelationship (with extra fields) is tried first.
    """

    type: Literal["bundle"] = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{_generate_uuid()}")
    objects: list[_BundleObject] = Field(default_factory=list)

    def confidence_annotated_relationships(self) -> list[ConfidenceAnnotatedRelationship]:
        """Return only the ConfidenceAnnotatedRelationship objects in this bundle."""
        return [obj for obj in self.objects if isinstance(obj, ConfidenceAnnotatedRelationship)]

    def mean_relationship_confidence(self) -> float | None:
        """Compute mean confidence across all annotated relationships.

        Returns None if no annotated relationships exist.
        """
        annotated = self.confidence_annotated_relationships()
        if not annotated:
            return None
        return sum(r.x_maljan_confidence for r in annotated) / len(annotated)
