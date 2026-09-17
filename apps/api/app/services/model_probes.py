"""Record what a probe reached, and refuse a job that names something it did not.

Two halves of one rule. The settings probes write down every ``(endpoint,
model)`` pair they reached, with the sentence they came back with; submitting a
job reads that record for every model its agents would call and refuses the
job when one of them has no passing result.

The refusal names the agent, the model and the probe's last message, because
those three are what an operator needs to fix it: which card in the console,
which field on it, and what the endpoint said. A model nothing has ever probed
is refused in the same breath with the one sentence that applies — that it has
not been tested — rather than being let through on the grounds that nothing is
known against it.

``core.llm.require_probe`` turns the whole gate off. It exists for the
air-gapped batch case, where the endpoint is known good and nobody is at a
console to press a button, and it is the only way past: there is deliberately
no per-job override, because a gate a submitter can wave away is not a gate.
"""

from __future__ import annotations

from typing import Any

from maljan.core.model_assignments import ModelAssignment, assignments_for
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger

logger = get_logger("services.model_probes")

# What a refusal says about a model no probe has ever been taken against.
NEVER_PROBED = "no probe has reached it"


async def record_probe(
    db: AsyncSession, *, endpoint: str, model: str, provider: str, ok: bool, detail: str
) -> None:
    """Write down what a probe reached, replacing this pair's previous answer.

    Per ``(endpoint, model)``: a second probe of the same pair is a newer
    answer to the same question, and two rows for it would leave the gate
    choosing between them.
    """
    if not str(model or "").strip() or not str(endpoint or "").strip():
        return
    from app.models.model_probe import ModelProbe

    row = (
        await db.execute(
            select(ModelProbe).where(ModelProbe.endpoint == endpoint, ModelProbe.model == model)
        )
    ).scalar_one_or_none()
    if row is None:
        db.add(
            ModelProbe(
                endpoint=endpoint,
                model=model,
                provider=str(provider or ""),
                ok=bool(ok),
                detail=str(detail or "")[:4000],
            )
        )
    else:
        row.provider = str(provider or "")
        row.ok = bool(ok)
        row.detail = str(detail or "")[:4000]
    await db.commit()


async def _results(db: AsyncSession, pairs: set[tuple[str, str]]) -> dict[tuple[str, str], Any]:
    """The stored results for the pairs asked about, keyed the way they are filed."""
    if not pairs:
        return {}
    from app.models.model_probe import ModelProbe

    endpoints = {endpoint for endpoint, _ in pairs}
    rows = (
        (await db.execute(select(ModelProbe).where(ModelProbe.endpoint.in_(endpoints))))
        .scalars()
        .all()
    )
    return {(row.endpoint, row.model): row for row in rows if (row.endpoint, row.model) in pairs}


def _sentence(assignment: ModelAssignment, detail: str) -> str:
    """One refusal, naming the agent, the model and what the probe last said."""
    return (
        f"agent {assignment.agent!r} names model {assignment.model!r} at "
        f"{assignment.endpoint}: {detail}"
    )


async def unprobed_models(db: AsyncSession, settings: Any, agents: list[str]) -> list[str]:
    """Every agent whose model has no passing probe, as sentences, or nothing.

    Empty when the gate is off, when the profile names no agent, and — the
    ordinary case — when every model an agent would call has been reached.
    """
    if not getattr(settings.llm, "require_probe", True):
        return []
    assignments = [a for a in assignments_for(settings, agents) if a.model and a.endpoint]
    stored = await _results(db, {a.key for a in assignments})
    refusals: list[str] = []
    for assignment in assignments:
        row = stored.get(assignment.key)
        if row is None:
            refusals.append(_sentence(assignment, NEVER_PROBED))
        elif not row.ok:
            refusals.append(_sentence(assignment, str(row.detail or "the probe did not reach it")))
    return refusals
