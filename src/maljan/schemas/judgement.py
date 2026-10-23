"""What the judge decides, as the judge's own structured answer.

Severity, malware category and family attribution used to be computed *around*
the judge: a CVSS-shaped arithmetic in the report builder, a keyword classifier
over analyst prose, and a grounding veto that zeroed a family name the judge
had already accepted. Three components each held one of these, none of them
had read the evidence, and the report presented all three as findings.

They are asked for here instead. The judge's verdict prompt requests them, the
model answers them alongside the STIX objects, ``pipeline.validation`` checks
them and hands back anything wrong for one retry, and the report prints what
comes out — including "not assessed" when nothing does.

The assessment rides on the bundle under ``x_maljan_assessment`` rather than as
bare bundle properties, because STIX 2.1 defines the Bundle's property set and
an ``x_``-prefixed name is how the spec says to add to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import UnionType
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel, Field, ValidationError

SEVERITY_RATINGS: tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Informational")

# The verdicts the judge may state, and the whole vocabulary the pipeline has:
# ``pipeline.outcome`` reads a run's verdict against these three and nothing
# else, and ``INCONCLUSIVE_VERDICT`` there is one of them rather than a fourth.
VERDICT_VALUES: tuple[str, ...] = ("Malware", "Suspicious", "Benign")

# The three, each under a name, unpacked from the tuple rather than spelled
# again: a check that compares a verdict to a literal of its own goes quiet the
# day the canonical word is renamed, and says nothing while it does.
MALWARE_VERDICT, SUSPICIOUS_VERDICT, BENIGN_VERDICT = VERDICT_VALUES

# What the sample's own hash indicator claims about the sample, per published
# verdict, in STIX 2.1's ``indicator-type-ov`` vocabulary. An exported bundle
# is acted on by tooling that reads the indicator and not the prose around it,
# so an indicator typed ``malicious-activity`` under a Benign verdict tells
# every blocklist the opposite of what the run concluded — a stronger
# contradiction than the malware object the export already declines, because a
# consumer blocks on the indicator.
#
# Here beside the vocabulary it is keyed on, so the two cannot drift. A verdict
# this table does not name is ``unknown``, which is the vocabulary's own word
# for a claim nobody is making.
INDICATOR_TYPE_BY_VERDICT: dict[str, str] = {
    "Malware": "malicious-activity",
    "Suspicious": "anomalous-activity",
    "Benign": "benign",
}
UNKNOWN_INDICATOR_TYPE = "unknown"

# Every value ``indicator-type-ov`` defines. The conformance test reads it; so
# does anything that wants to check an indicator this project emits against the
# vocabulary it claims to use.
INDICATOR_TYPES: frozenset[str] = frozenset(
    {
        "anomalous-activity",
        "anonymization",
        "attribution",
        "benign",
        "compromised",
        "malicious-activity",
        UNKNOWN_INDICATOR_TYPE,
    }
)


def indicator_type_for(verdict: Any) -> str:
    """What the sample's own indicator claims, for the verdict being published."""
    return INDICATOR_TYPE_BY_VERDICT.get(str(verdict or "").strip(), UNKNOWN_INDICATOR_TYPE)


class SeverityVerdict(BaseModel):
    """How bad this is, and why the judge says so.

    ``rating`` is a plain string and not a ``Literal``, deliberately. A model
    that answers "Catastrophic" has made a mistake worth telling it about, and
    a Literal would instead make the whole bundle fail to parse — the judge
    would silently fall back to a text verdict and nobody would learn that one
    word was wrong. ``pipeline.validation`` enforces the vocabulary and hands
    the judge the list; the schema carries what the judge actually said.
    """

    rating: str = Field(..., description=" | ".join(SEVERITY_RATINGS) + ".")
    rationale: str = Field(
        "", description="Why the evidence supports that rating, in one or two sentences."
    )


class FamilyVerdict(BaseModel):
    """Which malware family this is, and what the name was read from."""

    name: str = Field(..., description="Family name, e.g. 'AsyncRAT'.")
    # ``None`` when the judge put no number on the name: a default of 0.0
    # printed as "low confidence, 0.00", a confidence nobody stated.
    confidence: float | None = Field(
        None, ge=0.0, le=1.0, description="The judge's own confidence, if it stated one."
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Ledger entry ids the name was drawn from, e.g. ['ev_0012'].",
    )


class JudgeAssessment(BaseModel):
    """The non-STIX part of the verdict: the verdict itself, severity, category, family.

    Every field is optional because the judge is allowed to abstain, and an
    abstention has to survive to the report. A missing severity prints as "not
    assessed"; it does not fall back to a number some other component made up.

    ``verdict`` is asked for and is not optional in any other sense: the prompt
    requires it, ``pipeline.validation`` records a bundle that states none, and
    ``pipeline.outcome`` falls back to reading the object set only because a
    stored run may predate the field.

    Its annotation is ``Any`` and that is the point, for the reason
    ``SeverityVerdict.rating`` is a plain string: a ``Literal`` would fail the
    whole bundle over one wrong word, and the run would go down the text
    fallback with all of its objects, which is the failure the relocation pass
    exists to prevent. A type is one wrong word by another spelling — a judge
    answering ``["Malware"]`` or ``1`` to a field with three allowed values
    cost the same twenty-five objects while this was ``str | None``. Anything
    that is not one of the three words is read as stated and unrecognised, and
    the judge is told so with its own answer quoted back.
    """

    verdict: Any = Field(
        None,
        description=(
            " | ".join(VERDICT_VALUES)
            + ". Exactly one of those words and nothing else — no qualifier, no "
            "parenthesis, no sentence. The verdict this bundle states; the object set "
            "follows it. Anything to qualify it with goes in severity.rationale."
        ),
    )
    severity: SeverityVerdict | None = Field(
        None, description="The severity rating and its rationale."
    )
    malware_category: str | None = Field(
        None, description="Free-text behavioural category, e.g. 'ransomware'."
    )
    family: FamilyVerdict | None = Field(
        default=None, description="Family attribution with its evidence."
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "How sure the judge is of the verdict it stated above. The "
            "report's overall confidence, and the only source of it: a "
            "verdict the judge put no number on is published with none."
        ),
    )


# The enumerated words a leaf of the assessment is checked against, by the
# model and field that carry them. Read here only to fold a word written in
# another case onto the one word it names; ``pipeline.validation`` still asks
# about a word that names none. ``verdict`` is not here: its one reading is
# ``pipeline.outcome.normalise_verdict``, which already folds case.
_VOCABULARIES: dict[tuple[type[BaseModel], str], tuple[str, ...]] = {
    (SeverityVerdict, "rating"): SEVERITY_RATINGS,
}


@dataclass(frozen=True)
class LeafNote:
    """What reading one leaf of the assessment took, or why it could not be read.

    ``path`` is the leaf's place under the assessment (``"family.confidence"``;
    ``""`` for the assessment itself). ``readable`` is false when the leaf
    could not be read and was left absent; ``reason`` says why, in the
    schema's own words, or which reading was taken. ``read_as`` is what a
    readable leaf was read as.
    """

    path: str
    written: Any
    readable: bool
    reason: str
    read_as: Any = None


def _member(annotation: Any) -> Any:
    """The type an optional annotation holds: ``X`` for ``X | None``, else itself."""
    members = [a for a in get_args(annotation) if a is not type(None)]
    if get_origin(annotation) in (Union, UnionType) and len(members) == 1:
        return members[0]
    return annotation


def _model_in(annotation: Any) -> type[BaseModel] | None:
    member = _member(annotation)
    return member if isinstance(member, type) and issubclass(member, BaseModel) else None


def _one_required_str(model: type[BaseModel]) -> str | None:
    """The model's only required field when there is exactly one and it is a string."""
    required = [name for name, field in model.model_fields.items() if field.is_required()]
    if len(required) == 1 and model.model_fields[required[0]].annotation is str:
        return required[0]
    return None


def _loose(annotation: Any, written: Any) -> tuple[Any, str] | None:
    """The one reading of a value written in the wrong type, or ``None`` when there is none.

    A list of one where one value is asked is that value; a string where a
    list of strings is asked is a list of that one string, when it holds no
    separator. Nothing else: a number is never rescaled, and a value with two
    readings has none — ``"ev_0001, ev_0002"`` is one id or two, and the
    judge is asked which.
    """
    member = _member(annotation)
    if (
        member in (str, int, float)
        and isinstance(written, list)
        and len(written) == 1
        and not isinstance(written[0], (list, dict))
    ):
        return written[0], "a list of one value, read as that value"
    if (
        get_origin(member) is list
        and get_args(member) == (str,)
        and isinstance(written, str)
        and written.strip()
        and not _SEPARATOR.search(written.strip())
    ):
        return [written], "a string, read as a list of that one string"
    return None


# What makes a string more than one item of a list: whitespace, a comma or a
# semicolon between its characters.
_SEPARATOR = re.compile(r"[\s,;]")


def _names_nothing(value: str) -> bool:
    """Whether ``value`` is a placeholder for "none" (``reporting.models.NO_FAMILY_WORDS``)."""
    from maljan.reporting.models import stated_family

    return not stated_family(value)


def _folded(model: type[BaseModel], name: str, value: Any) -> Any:
    """The enumerated word ``value`` names in another case, or ``value`` unchanged."""
    words = _VOCABULARIES.get((model, name))
    if not words or not isinstance(value, str) or value in words:
        return value
    matches = [word for word in words if word.casefold() == value.strip().casefold()]
    return matches[0] if len(matches) == 1 else value


def _first_error(error: ValidationError) -> str:
    errors = error.errors()
    return str(errors[0].get("msg", "")) if errors else str(error)


def _fits(model: type[BaseModel], name: str, value: Any) -> ValidationError | None:
    """Why ``model`` refuses ``value`` for its field ``name``, or ``None`` when it takes it."""
    try:
        model.__pydantic_validator__.validate_assignment(model.model_construct(), name, value)
    except ValidationError as refused:
        return refused
    return None


def _read_model(
    model: type[BaseModel], written: Any, path: str, notes: list[LeafNote]
) -> dict[str, Any] | None:
    """``written`` as the keys ``model`` can read, with each unreadable leaf left out.

    ``None`` when the object as a whole cannot be read: it is not an object,
    or a field it requires could not be read or was not written. Every
    reading taken and every leaf left out is appended to ``notes``.
    """
    mark = len(notes)
    value = written
    readings: list[str] = []
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
        readings.append("a list of one item, read as that item")
    required = _one_required_str(model)
    if isinstance(value, str) and value.strip() and required is not None:
        if _names_nothing(value):
            # "Unknown" where an object is asked is an abstention, not a name:
            # the judge is asked, and no object is made of it.
            notes.append(LeafNote(path, written, False, f"a placeholder that names no {required}"))
            return None
        value = {required: value}
        readings.append(f"a string where an object is asked, read as its {required}")
    if not isinstance(value, dict):
        notes.append(
            LeafNote(path, written, False, f"Input should be an object of {model.__name__}")
        )
        return None
    cleaned: dict[str, Any] = {}
    # Why each leaf left out could not be read, so an object absent for want
    # of a field it requires says why that field was not read.
    dropped: dict[str, str] = {}
    for key, leaf in value.items():
        field = model.model_fields.get(key) if isinstance(key, str) else None
        if field is None:
            cleaned[key] = leaf
            continue
        where = f"{path}.{key}" if path else key
        nested = _model_in(field.annotation)
        if nested is not None and leaf is not None:
            read = _read_model(nested, leaf, where, notes)
            if read is not None:
                cleaned[key] = read
            else:
                dropped[key] = notes[-1].reason
            continue
        if isinstance(leaf, bool) and _member(field.annotation) in (int, float):
            # The schema's lax mode reads true as 1.0 and false as 0.0, and
            # stored runs load through it; a judge's answer is not read so: a
            # yes or no is not a number, and the judge is asked for one.
            reason = "Input should be a number, not true or false"
            notes.append(LeafNote(where, leaf, False, reason))
            dropped[key] = reason
            continue
        candidate, leaf_readings = leaf, []
        refused = _fits(model, key, _folded(model, key, leaf))
        if refused is not None:
            other = _loose(field.annotation, leaf)
            if other is None or _fits(model, key, _folded(model, key, other[0])) is not None:
                notes.append(LeafNote(where, leaf, False, _first_error(refused)))
                dropped[key] = _first_error(refused)
                continue
            candidate = other[0]
            leaf_readings.append(other[1])
        folded = _folded(model, key, candidate)
        if folded != candidate:
            candidate = folded
            leaf_readings.append(
                "a word of the vocabulary written in another case, read as that word"
            )
        cleaned[key] = candidate
        if leaf_readings:
            notes.append(LeafNote(where, leaf, True, "; then ".join(leaf_readings), candidate))
    try:
        model.model_validate(cleaned)
    except ValidationError as refused:
        # A field it requires could not be read or was not written: the object
        # is absent whole, and no reading of its other leaves took effect. A
        # field left out for its type says so, rather than "Field required".
        missing = next(
            (
                str(error["loc"][0])
                for error in refused.errors()
                if error.get("loc") and str(error["loc"][0]) in dropped
            ),
            None,
        )
        reason = f"{missing}: {dropped[missing]}" if missing else _first_error(refused)
        del notes[mark:]
        notes.append(LeafNote(path, written, False, reason))
        return None
    if readings:
        notes.insert(mark, LeafNote(path, written, True, "; then ".join(readings), cleaned))
    return cleaned


def read_assessment(written: Any) -> tuple[JudgeAssessment | None, list[LeafNote]]:
    """The judge's assessment read leaf by leaf, and what each reading took.

    A leaf whose type is wrong in a way with one reading — a list of one value
    where one is asked, a string with no separator where a list of strings is
    asked, a string where an object with one required string is asked (unless
    it is a placeholder for "none", such as "Unknown") — is read so, and the
    reading is noted. A severity rating written in another case ("high") is
    folded onto the rating it names, and noted. A leaf that cannot be read is
    left absent and noted with the schema's reason; nothing is guessed, so a
    confidence of 85 where 0..1 is asked is absent, not 0.85, and ``true``
    where a number is asked is absent, not 1.0. Any other
    assessment reads as ``JudgeAssessment.model_validate`` reads it, with no
    notes. ``None`` when the whole cannot be read as an object. Linear in the
    size of what was written.
    """
    notes: list[LeafNote] = []
    cleaned = _read_model(JudgeAssessment, written, "", notes)
    if cleaned is None:
        return None, notes
    return JudgeAssessment.model_validate(cleaned), notes
