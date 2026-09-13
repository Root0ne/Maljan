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

from pydantic import BaseModel, Field

SEVERITY_RATINGS: tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Informational")


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
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="The judge's own confidence.")
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Ledger entry ids the name was drawn from, e.g. ['ev_0012'].",
    )


class JudgeAssessment(BaseModel):
    """The non-STIX part of the verdict: severity, category, family.

    Every field is optional because the judge is allowed to abstain, and an
    abstention has to survive to the report. A missing severity prints as "not
    assessed"; it does not fall back to a number some other component made up.
    """

    severity: SeverityVerdict | None = Field(
        None, description="The severity rating and its rationale."
    )
    malware_category: str | None = Field(
        None, description="Free-text behavioural category, e.g. 'ransomware'."
    )
    family: FamilyVerdict | None = Field(None, description="Family attribution with its evidence.")
