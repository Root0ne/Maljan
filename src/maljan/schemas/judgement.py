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

from typing import Any

from pydantic import BaseModel, Field

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
